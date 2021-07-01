/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2021 The noVNC Authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 */

// The maximum allowable de-sync, in seconds. If the time between the last
// received timestamp and the current audio playback timestamp exceeds this
// value, the audio stream will be seeked to the most current timestamp
// possible.
const MAX_ALLOWABLE_DESYNC = 0.5;

// The amount of time, in seconds, to keep in the audio buffer while seeking.
// Whenever a de-sync event happens and we need to seek to a future
// timestamp, we skip to the last buffered time minus this amount, so that the
// browser has this amount of time worth of buffered audio data. This is done
// to avoid having the browser enter a buffering state just after seeking.
const SEEK_BUFFER_LENGTH = 0.2;

// An audio stream built upon Media Stream Extensions.
export default class AudioStream {
    constructor(codec) {
        this._codec = codec;
        this._reset();
    }

    _reset() {
        // Instantiate a media source and audio buffer/queue.
        this._mediaSource = new MediaSource();
        this._audioBuffer = null;
        this._audioQ = [];

        // Create a hidden audio element.
        this._audio = document.createElement("audio");
        this._audio.src = window.URL.createObjectURL(this._mediaSource);

        // When data is queued, start playing.
        this._audio.autoplay = true;
        this._mediaSource.addEventListener(
            "sourceopen",
            this._onSourceOpen.bind(this),
            false
        );
        this._audio.addEventListener(
            "error",
            (ev) => {
                console.error("Audio element error", ev);
            },
            false
        );
        this._audio.addEventListener("canplay", () => {
            try {
                this._audio.play();
            } catch (e) {
                // Firefox and Chrome are totally cool with playing this
                // the moment we can do it, but Safari throws an exception
                // since play() is not called in a stack that ran a user
                // event handler.
            }
        });
    }

    _onSourceOpen(e) {
        if (this._audioBuffer) {
            return;
        }
        this._audioBuffer = this._mediaSource.addSourceBuffer(this._codec);
        this._audioBuffer.mode = "segments";
        this._audioBuffer.addEventListener(
            "updateend",
            this._onUpdateBuffer.bind(this)
        );
        this._audioBuffer.addEventListener("error", (ev) => {
            console.error("AudioBuffer error", ev);
        });
    }

    _onUpdateBuffer() {
        if (
            !this._audioBuffer ||
            this._audioBuffer.updating ||
            this._audio.error
        ) {
            // The audio buffer is not yet ready to accept any new data.
            return;
        }
        if (!this._audioQ.length) {
            // There's nothing to append.
            return;
        }

        const timestamp = this._audioQ[0][0];
        if (this._audioQ.length === 1) {
            this._appendChunk(timestamp, this._audioQ.pop()[1]);
            return;
        }

        // If there is more than one chunk in the queue, they are coalesced
        // into a single buffer. This is because following appendBuffer(),
        // the audio buffer changes to an "updating" state for a small amount
        // of time and any new chunks won't be able to be appended immediately.
        // Since the internal queue is used when the browser is trying to catch
        // up with the server, we want to have the audio buffer unappendable
        // for a smaller amount of time.
        let chunkLength = 0;
        for (let i = 0; i < this._audioQ.length; ++i) {
            chunkLength += this._audioQ[i][1].byteLength;
        }
        const chunk = new Uint8Array(chunkLength);
        let offset = 0;
        for (let i = 0; i < this._audioQ.length; ++i) {
            chunk.set(new Uint8Array(this._audioQ[i][1]), offset);
            offset += this._audioQ[i][1].byteLength;
        }
        this._audioQ.splice(0, this._audioQ.length);
        this._appendChunk(timestamp, chunk);
    }

    // Append a chunk into the AudioBuffer. The caller should ensure that
    // the AudioBuffer is ready to receive the chunk. If the difference
    // between the current playback position of the audio and the timestamp
    // exceeds the maximum allowable desync threshold, the audio will be
    // seeked to the latest possible position that doesn't trigger buffering
    // to avoid an arbitrarily large desync between video and audio.
    _appendChunk(timestamp, chunk) {
        this._audioBuffer.appendBuffer(chunk);
        if (
            timestamp - this._audio.currentTime > MAX_ALLOWABLE_DESYNC &&
            (this._audio.seekable.length || this._audio.buffered.length)
        ) {
            console.debug("maximum allowable desync reached", {
                readyState: this._audio.readyState,
                buffered: (
                    (this._audio.buffered &&
                        this._audio.buffered.length &&
                        this._audio.buffered.end(
                            this._audio.buffered.length - 1
                        )) ||
                    0
                ).toFixed(2),
                seekable: (
                    (this._audio.seekable &&
                        this._audio.seekable.length &&
                        this._audio.seekable.end(
                            this._audio.seekable.length - 1
                        )) ||
                    0
                ).toFixed(2),
                time: this._audio.currentTime.toFixed(2),
                delta: (timestamp - this._audio.currentTime).toFixed(2)
            });
            if (this._audio.buffered && this._audio.buffered.length) {
                this._audio.currentTime =
                    this._audio.buffered.end(this._audio.buffered.length - 1) -
                    SEEK_BUFFER_LENGTH;
            } else {
                this._audio.currentTime =
                    this._audio.seekable.end(this._audio.seekable.length - 1) -
                    SEEK_BUFFER_LENGTH;
            }
        }
    }

    // Queues an audio chunk at a particular timestamp.
    queueAudioFrame(timestamp, keyframe, chunk) {
        // If the MSE audio buffer is not ready to receive the chunk or
        // there are some other chunks waiting to be appended, we save
        // a copy of it into our own internal queue. Eventually,
        // when it becomes ready, we append all pending chunks at once.
        if (
            this._audioBuffer === null ||
            this._audioBuffer.updating ||
            this._audio.error ||
            this._audioQ.length
        ) {
            // We need to make a copy, since `chunk` is a view of the underlying
            // buffer owned by Websock, and will be mutated once we return.
            // TODO: `keyframe` can be used to decide when to drop a chunk if
            // there's enough backpressure.
            const copy = new ArrayBuffer(chunk.byteLength);
            new Uint8Array(copy).set(new Uint8Array(chunk));
            this._audioQ.push([timestamp, copy]);
            this._onUpdateBuffer();
            return;
        }

        this._appendChunk(timestamp, chunk);
    }

    close() {
        if (this._audio) {
            this._audio.pause();
        }
        this._mediaSource = null;
        this._audioBuffer = null;
        this._audioQ = [];
        this._audio = null;
    }
}
