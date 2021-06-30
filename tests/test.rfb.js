const expect = chai.expect;

import RFB from '../core/rfb.js';
import Websock from '../core/websock.js';
import ZStream from "../vendor/pako/lib/zlib/zstream.js";
import { deflateInit, deflate } from "../vendor/pako/lib/zlib/deflate.js";
import { encodings } from '../core/encodings.js';
import { toUnsigned32bit } from '../core/util/int.js';
import { encodeUTF8 } from '../core/util/strings.js';
import KeyTable from '../core/input/keysym.js';

import FakeWebSocket from './fake.websocket.js';

function push8(arr, num) {
    "use strict";
    arr.push(num & 0xFF);
}

function push16(arr, num) {
    "use strict";
    arr.push((num >> 8) & 0xFF,
             num & 0xFF);
}

function push32(arr, num) {
    "use strict";
    arr.push((num >> 24) & 0xFF,
             (num >> 16) & 0xFF,
             (num >>  8) & 0xFF,
             num & 0xFF);
}

function pushString(arr, string) {
    let utf8 = unescape(encodeURIComponent(string));
    for (let i = 0; i < utf8.length; i++) {
        arr.push(utf8.charCodeAt(i));
    }
}

function deflateWithSize(data) {
    // Adds the size of the string in front before deflating

    let unCompData = [];
    unCompData.push((data.length >> 24) & 0xFF,
                    (data.length >> 16) & 0xFF,
                    (data.length >>  8) & 0xFF,
                    (data.length & 0xFF));

    for (let i = 0; i < data.length; i++) {
        unCompData.push(data.charCodeAt(i));
    }

    let strm = new ZStream();
    let chunkSize = 1024 * 10 * 10;
    strm.output = new Uint8Array(chunkSize);
    deflateInit(strm, 5);

    /* eslint-disable camelcase */
    strm.input = unCompData;
    strm.avail_in = strm.input.length;
    strm.next_in = 0;
    strm.next_out = 0;
    strm.avail_out = chunkSize;
    /* eslint-enable camelcase */

    deflate(strm, 3);

    return new Uint8Array(strm.output.buffer, 0, strm.next_out);
}

describe('Remote Frame Buffer Protocol Client', function () {
    let clock;
    let raf;

    before(FakeWebSocket.replace);
    after(FakeWebSocket.restore);

    before(function () {
        this.clock = clock = sinon.useFakeTimers(Date.now());
        // sinon doesn't support this yet
        raf = window.requestAnimationFrame;
        window.requestAnimationFrame = setTimeout;
        // Use a single set of buffers instead of reallocating to
        // speed up tests
        const sock = new Websock();
        const _sQ = new Uint8Array(sock._sQbufferSize);
        const rQ = new Uint8Array(sock._rQbufferSize);

        Websock.prototype._oldAllocateBuffers = Websock.prototype._allocateBuffers;
        Websock.prototype._allocateBuffers = function () {
            this._sQ = _sQ;
            this._rQ = rQ;
        };

        // Avoiding printing the entire Websock buffer on errors
        Websock.prototype.toString = function () { return "[object Websock]"; };
    });

    after(function () {
        delete Websock.prototype.toString;
        this.clock.restore();
        window.requestAnimationFrame = raf;
    });

    let container;
    let rfbs;

    beforeEach(function () {
        // Create a container element for all RFB objects to attach to
        container = document.createElement('div');
        container.style.width = "100%";
        container.style.height = "100%";
        document.body.appendChild(container);

        // And track all created RFB objects
        rfbs = [];
    });
    afterEach(function () {
        // Make sure every created RFB object is properly cleaned up
        // or they might affect subsequent tests
        rfbs.forEach(function (rfb) {
            rfb.disconnect();
            expect(rfb._disconnect).to.have.been.called;
        });
        rfbs = [];

        document.body.removeChild(container);
        container = null;
    });

    function makeRFB(url, options) {
        url = url || 'wss://host:8675';
        const rfb = new RFB(container, url, options);
        clock.tick();
        rfb._sock._websocket._open();
        rfb._rfbConnectionState = 'connected';
        sinon.spy(rfb, "_disconnect");
        rfbs.push(rfb);
        return rfb;
    }

    describe('Connecting/Disconnecting', function () {
        describe('#RFB (constructor)', function () {
            let open, attach;
            beforeEach(function () {
                open = sinon.spy(Websock.prototype, 'open');
                attach = sinon.spy(Websock.prototype, 'attach');
            });
            afterEach(function () {
                open.restore();
                attach.restore();
            });

            it('should actually connect to the websocket', function () {
                new RFB(document.createElement('div'), 'ws://HOST:8675/PATH');
                expect(open).to.have.been.calledOnceWithExactly('ws://HOST:8675/PATH', []);
            });

            it('should pass on connection problems', function () {
                open.restore();
                open = sinon.stub(Websock.prototype, 'open');
                open.throws(new Error('Failure'));
                expect(() => new RFB(document.createElement('div'), 'ws://HOST:8675/PATH')).to.throw('Failure');
            });

            it('should handle WebSocket/RTCDataChannel objects', function () {
                let sock = new FakeWebSocket('ws://HOST:8675/PATH', []);
                new RFB(document.createElement('div'), sock);
                expect(open).to.not.have.been.called;
                expect(attach).to.have.been.calledOnceWithExactly(sock);
            });

            it('should handle already open WebSocket/RTCDataChannel objects', function () {
                let sock = new FakeWebSocket('ws://HOST:8675/PATH', []);
                sock._open();
                const client = new RFB(document.createElement('div'), sock);
                let callback = sinon.spy();
                client.addEventListener('disconnect', callback);
                expect(open).to.not.have.been.called;
                expect(attach).to.have.been.calledOnceWithExactly(sock);
                // Check if it is ready for some data
                sock._receiveData(new Uint8Array(['R', 'F', 'B', '0', '0', '3', '0', '0', '8']));
                expect(callback).to.not.have.been.called;
            });

            it('should refuse closed WebSocket/RTCDataChannel objects', function () {
                let sock = new FakeWebSocket('ws://HOST:8675/PATH', []);
                sock.readyState = WebSocket.CLOSED;
                expect(() => new RFB(document.createElement('div'), sock)).to.throw();
            });

            it('should pass on attach problems', function () {
                attach.restore();
                attach = sinon.stub(Websock.prototype, 'attach');
                attach.throws(new Error('Failure'));
                let sock = new FakeWebSocket('ws://HOST:8675/PATH', []);
                expect(() => new RFB(document.createElement('div'), sock)).to.throw('Failure');
            });
        });

        describe('#disconnect', function () {
            let client;
            let close;

            beforeEach(function () {
                client = makeRFB();
                close = sinon.stub(Websock.prototype, "close");
            });
            afterEach(function () {
                close.restore();
            });

            it('should start closing WebSocket', function () {
                let callback = sinon.spy();
                client.addEventListener('disconnect', callback);
                client.disconnect();
                expect(close).to.have.been.calledOnceWithExactly();
                expect(callback).to.not.have.been.called;
            });

            it('should send disconnect event', function () {
                let callback = sinon.spy();
                client.addEventListener('disconnect', callback);
                client.disconnect();
                close.thisValues[0]._eventHandlers.close(new CloseEvent("close", { 'code': 1000, 'reason': "", 'wasClean': true }));
                expect(callback).to.have.been.calledOnce;
                expect(callback.args[0][0].detail.clean).to.be.true;
            });

            it('should force disconnect if disconnecting takes too long', function () {
                let callback = sinon.spy();
                client.addEventListener('disconnect', callback);
                client.disconnect();
                this.clock.tick(3 * 1000);
                expect(callback).to.have.been.calledOnce;
                expect(callback.args[0][0].detail.clean).to.be.true;
            });

            it('should not fail if disconnect completes before timeout', function () {
                let callback = sinon.spy();
                client.addEventListener('disconnect', callback);
                client.disconnect();
                client._updateConnectionState('disconnecting');
                this.clock.tick(3 * 1000 / 2);
                close.thisValues[0]._eventHandlers.close(new CloseEvent("close", { 'code': 1000, 'reason': "", 'wasClean': true }));
                this.clock.tick(3 * 1000 / 2 + 1);
                expect(callback).to.have.been.calledOnce;
                expect(callback.args[0][0].detail.clean).to.be.true;
            });

            it('should unregister error event handler', function () {
                sinon.spy(client._sock, 'off');
                client.disconnect();
                expect(client._sock.off).to.have.been.calledWith('error');
            });

            it('should unregister message event handler', function () {
                sinon.spy(client._sock, 'off');
                client.disconnect();
                expect(client._sock.off).to.have.been.calledWith('message');
            });

            it('should unregister open event handler', function () {
                sinon.spy(client._sock, 'off');
                client.disconnect();
                expect(client._sock.off).to.have.been.calledWith('open');
            });
        });

        describe('#sendCredentials', function () {
            let client;
            beforeEach(function () {
                client = makeRFB();
                client._rfbConnectionState = 'connecting';
            });

            it('should set the rfb credentials properly"', function () {
                client.sendCredentials({ password: 'pass' });
                expect(client._rfbCredentials).to.deep.equal({ password: 'pass' });
            });

            it('should call initMsg "soon"', function () {
                client._initMsg = sinon.spy();
                client.sendCredentials({ password: 'pass' });
                this.clock.tick(5);
                expect(client._initMsg).to.have.been.calledOnce;
            });
        });
    });

    describe('Public API Basic Behavior', function () {
        let client;
        beforeEach(function () {
            client = makeRFB();
        });

        describe('#sendCtrlAlDel', function () {
            it('should sent ctrl[down]-alt[down]-del[down] then del[up]-alt[up]-ctrl[up]', function () {
                const expected = {_sQ: new Uint8Array(48), _sQlen: 0, flush: () => {}};
                RFB.messages.keyEvent(expected, 0xFFE3, 1);
                RFB.messages.keyEvent(expected, 0xFFE9, 1);
                RFB.messages.keyEvent(expected, 0xFFFF, 1);
                RFB.messages.keyEvent(expected, 0xFFFF, 0);
                RFB.messages.keyEvent(expected, 0xFFE9, 0);
                RFB.messages.keyEvent(expected, 0xFFE3, 0);

                client.sendCtrlAltDel();
                expect(client._sock).to.have.sent(expected._sQ);
            });

            it('should not send the keys if we are not in a normal state', function () {
                sinon.spy(client._sock, 'flush');
                client._rfbConnectionState = "connecting";
                client.sendCtrlAltDel();
                expect(client._sock.flush).to.not.have.been.called;
            });

            it('should not send the keys if we are set as view_only', function () {
                sinon.spy(client._sock, 'flush');
                client._viewOnly = true;
                client.sendCtrlAltDel();
                expect(client._sock.flush).to.not.have.been.called;
            });
        });

        describe('#sendKey', function () {
            it('should send a single key with the given code and state (down = true)', function () {
                const expected = {_sQ: new Uint8Array(8), _sQlen: 0, flush: () => {}};
                RFB.messages.keyEvent(expected, 123, 1);
                client.sendKey(123, 'Key123', true);
                expect(client._sock).to.have.sent(expected._sQ);
            });

            it('should send both a down and up event if the state is not specified', function () {
                const expected = {_sQ: new Uint8Array(16), _sQlen: 0, flush: () => {}};
                RFB.messages.keyEvent(expected, 123, 1);
                RFB.messages.keyEvent(expected, 123, 0);
                client.sendKey(123, 'Key123');
                expect(client._sock).to.have.sent(expected._sQ);
            });

            it('should not send the key if we are not in a normal state', function () {
                sinon.spy(client._sock, 'flush');
                client._rfbConnectionState = "connecting";
                client.sendKey(123, 'Key123');
                expect(client._sock.flush).to.not.have.been.called;
            });

            it('should not send the key if we are set as view_only', function () {
                sinon.spy(client._sock, 'flush');
                client._viewOnly = true;
                client.sendKey(123, 'Key123');
                expect(client._sock.flush).to.not.have.been.called;
            });

            it('should send QEMU extended events if supported', function () {
                client._qemuExtKeyEventSupported = true;
                const expected = {_sQ: new Uint8Array(12), _sQlen: 0, flush: () => {}};
                RFB.messages.QEMUExtendedKeyEvent(expected, 0x20, true, 0x0039);
                client.sendKey(0x20, 'Space', true);
                expect(client._sock).to.have.sent(expected._sQ);
            });

            it('should not send QEMU extended events if unknown key code', function () {
                client._qemuExtKeyEventSupported = true;
                const expected = {_sQ: new Uint8Array(8), _sQlen: 0, flush: () => {}};
                RFB.messages.keyEvent(expected, 123, 1);
                client.sendKey(123, 'FooBar', true);
                expect(client._sock).to.have.sent(expected._sQ);
            });
        });

        describe('#focus', function () {
            it('should move focus to canvas object', function () {
                client._canvas.focus = sinon.spy();
                client.focus();
                expect(client._canvas.focus).to.have.been.calledOnce;
            });
        });

        describe('#blur', function () {
            it('should remove focus from canvas object', function () {
                client._canvas.blur = sinon.spy();
                client.blur();
                expect(client._canvas.blur).to.have.been.calledOnce;
            });
        });

        describe('#clipboardPasteFrom', function () {
            describe('Clipboard update handling', function () {
                beforeEach(function () {
                    sinon.spy(RFB.messages, 'clientCutText');
                    sinon.spy(RFB.messages, 'extendedClipboardNotify');
                });

                afterEach(function () {
                    RFB.messages.clientCutText.restore();
                    RFB.messages.extendedClipboardNotify.restore();
                });

                it('should send the given text in an clipboard update', function () {
                    client.clipboardPasteFrom('abc');

                    expect(RFB.messages.clientCutText).to.have.been.calledOnce;
                    expect(RFB.messages.clientCutText).to.have.been.calledWith(client._sock,
                                                                               new Uint8Array([97, 98, 99]));
                });

                it('should send an notify if extended clipboard is supported by server', function () {
                    // Send our capabilities
                    let data = [3, 0, 0, 0];
                    const flags = [0x1F, 0x00, 0x00, 0x01];
                    let fileSizes = [0x00, 0x00, 0x00, 0x1E];

                    push32(data, toUnsigned32bit(-8));
                    data = data.concat(flags);
                    data = data.concat(fileSizes);
                    client._sock._websocket._receiveData(new Uint8Array(data));

                    client.clipboardPasteFrom('extended test');
                    expect(RFB.messages.extendedClipboardNotify).to.have.been.calledOnce;
                });
            });

            it('should flush multiple times for large clipboards', function () {
                sinon.spy(client._sock, 'flush');
                let longText = "";
                for (let i = 0; i < client._sock._sQbufferSize + 100; i++) {
                    longText += 'a';
                }
                client.clipboardPasteFrom(longText);
                expect(client._sock.flush).to.have.been.calledTwice;
            });

            it('should not send the text if we are not in a normal state', function () {
                sinon.spy(client._sock, 'flush');
                client._rfbConnectionState = "connecting";
                client.clipboardPasteFrom('abc');
                expect(client._sock.flush).to.not.have.been.called;
            });
        });

        describe("XVP operations", function () {
            beforeEach(function () {
                client._rfbXvpVer = 1;
            });

            it('should send the shutdown signal on #machineShutdown', function () {
                client.machineShutdown();
                expect(client._sock).to.have.sent(new Uint8Array([0xFA, 0x00, 0x01, 0x02]));
            });

            it('should send the reboot signal on #machineReboot', function () {
                client.machineReboot();
                expect(client._sock).to.have.sent(new Uint8Array([0xFA, 0x00, 0x01, 0x03]));
            });

            it('should send the reset signal on #machineReset', function () {
                client.machineReset();
                expect(client._sock).to.have.sent(new Uint8Array([0xFA, 0x00, 0x01, 0x04]));
            });

            it('should not send XVP operations with higher versions than we support', function () {
                sinon.spy(client._sock, 'flush');
                client._xvpOp(2, 7);
                expect(client._sock.flush).to.not.have.been.called;
            });
        });
    });

    describe('Clipping', function () {
        let client;
        beforeEach(function () {
            client = makeRFB();
            container.style.width = '70px';
            container.style.height = '80px';
            client.clipViewport = true;
        });

        it('should update display clip state when changing the property', function () {
            const spy = sinon.spy(client._display, "clipViewport", ["set"]);

            client.clipViewport = false;
            expect(spy.set).to.have.been.calledOnce;
            expect(spy.set).to.have.been.calledWith(false);
            spy.set.resetHistory();

            client.clipViewport = true;
            expect(spy.set).to.have.been.calledOnce;
            expect(spy.set).to.have.been.calledWith(true);
        });

        it('should update the viewport when the container size changes', function () {
            sinon.spy(client._display, "viewportChangeSize");

            container.style.width = '40px';
            container.style.height = '50px';
            const event = new UIEvent('resize');
            window.dispatchEvent(event);
            clock.tick();

            expect(client._display.viewportChangeSize).to.have.been.calledOnce;
            expect(client._display.viewportChangeSize).to.have.been.calledWith(40, 50);
        });

        it('should update the viewport when the remote session resizes', function () {
            // Simple ExtendedDesktopSize FBU message
            const incoming = [ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0xff, 0x00, 0xff, 0xff, 0xff, 0xfe, 0xcc,
                               0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff,
                               0x00, 0x00, 0x00, 0x00 ];

            sinon.spy(client._display, "viewportChangeSize");

            client._sock._websocket._receiveData(new Uint8Array(incoming));

            // FIXME: Display implicitly calls viewportChangeSize() when
            //        resizing the framebuffer, hence calledTwice.
            expect(client._display.viewportChangeSize).to.have.been.calledTwice;
            expect(client._display.viewportChangeSize).to.have.been.calledWith(70, 80);
        });

        it('should not update the viewport if not clipping', function () {
            client.clipViewport = false;
            sinon.spy(client._display, "viewportChangeSize");

            container.style.width = '40px';
            container.style.height = '50px';
            const event = new UIEvent('resize');
            window.dispatchEvent(event);
            clock.tick();

            expect(client._display.viewportChangeSize).to.not.have.been.called;
        });

        it('should not update the viewport if scaling', function () {
            client.scaleViewport = true;
            sinon.spy(client._display, "viewportChangeSize");

            container.style.width = '40px';
            container.style.height = '50px';
            const event = new UIEvent('resize');
            window.dispatchEvent(event);
            clock.tick();

            expect(client._display.viewportChangeSize).to.not.have.been.called;
        });

        describe('Dragging', function () {
            beforeEach(function () {
                client.dragViewport = true;
                sinon.spy(RFB.messages, "pointerEvent");
            });

            afterEach(function () {
                RFB.messages.pointerEvent.restore();
            });

            it('should not send button messages when initiating viewport dragging', function () {
                client._handleMouseButton(13, 9, 0x001);
                expect(RFB.messages.pointerEvent).to.not.have.been.called;
            });

            it('should send button messages when release without movement', function () {
                // Just up and down
                client._handleMouseButton(13, 9, 0x001);
                client._handleMouseButton(13, 9, 0x000);
                expect(RFB.messages.pointerEvent).to.have.been.calledTwice;

                RFB.messages.pointerEvent.resetHistory();

                // Small movement
                client._handleMouseButton(13, 9, 0x001);
                client._handleMouseMove(15, 14);
                client._handleMouseButton(15, 14, 0x000);
                expect(RFB.messages.pointerEvent).to.have.been.calledTwice;
            });

            it('should not send button messages when in view only', function () {
                client._viewOnly = true;
                client._handleMouseButton(13, 9, 0x001);
                client._handleMouseButton(13, 9, 0x000);
                expect(RFB.messages.pointerEvent).to.not.have.been.called;
            });

            it('should send button message directly when drag is disabled', function () {
                client.dragViewport = false;
                client._handleMouseButton(13, 9, 0x001);
                expect(RFB.messages.pointerEvent).to.have.been.calledOnce;
            });

            it('should be initiate viewport dragging on sufficient movement', function () {
                sinon.spy(client._display, "viewportChangePos");

                // Too small movement

                client._handleMouseButton(13, 9, 0x001);
                client._handleMouseMove(18, 9);

                expect(RFB.messages.pointerEvent).to.not.have.been.called;
                expect(client._display.viewportChangePos).to.not.have.been.called;

                // Sufficient movement

                client._handleMouseMove(43, 9);

                expect(RFB.messages.pointerEvent).to.not.have.been.called;
                expect(client._display.viewportChangePos).to.have.been.calledOnce;
                expect(client._display.viewportChangePos).to.have.been.calledWith(-30, 0);

                client._display.viewportChangePos.resetHistory();

                // Now a small movement should move right away

                client._handleMouseMove(43, 14);

                expect(RFB.messages.pointerEvent).to.not.have.been.called;
                expect(client._display.viewportChangePos).to.have.been.calledOnce;
                expect(client._display.viewportChangePos).to.have.been.calledWith(0, -5);
            });

            it('should not send button messages when dragging ends', function () {
                // First the movement

                client._handleMouseButton(13, 9, 0x001);
                client._handleMouseMove(43, 9);
                client._handleMouseButton(43, 9, 0x000);

                expect(RFB.messages.pointerEvent).to.not.have.been.called;
            });

            it('should terminate viewport dragging on a button up event', function () {
                // First the dragging movement

                client._handleMouseButton(13, 9, 0x001);
                client._handleMouseMove(43, 9);
                client._handleMouseButton(43, 9, 0x000);

                // Another movement now should not move the viewport

                sinon.spy(client._display, "viewportChangePos");

                client._handleMouseMove(43, 59);

                expect(client._display.viewportChangePos).to.not.have.been.called;
            });
        });
    });

    describe('Scaling', function () {
        let client;
        beforeEach(function () {
            client = makeRFB();
            container.style.width = '70px';
            container.style.height = '80px';
            client.scaleViewport = true;
        });

        it('should update display scale factor when changing the property', function () {
            const spy = sinon.spy(client._display, "scale", ["set"]);
            sinon.spy(client._display, "autoscale");

            client.scaleViewport = false;
            expect(spy.set).to.have.been.calledOnce;
            expect(spy.set).to.have.been.calledWith(1.0);
            expect(client._display.autoscale).to.not.have.been.called;

            client.scaleViewport = true;
            expect(client._display.autoscale).to.have.been.calledOnce;
            expect(client._display.autoscale).to.have.been.calledWith(70, 80);
        });

        it('should update the clipping setting when changing the property', function () {
            client.clipViewport = true;

            const spy = sinon.spy(client._display, "clipViewport", ["set"]);

            client.scaleViewport = false;
            expect(spy.set).to.have.been.calledOnce;
            expect(spy.set).to.have.been.calledWith(true);

            spy.set.resetHistory();

            client.scaleViewport = true;
            expect(spy.set).to.have.been.calledOnce;
            expect(spy.set).to.have.been.calledWith(false);
        });

        it('should update the scaling when the container size changes', function () {
            sinon.spy(client._display, "autoscale");

            container.style.width = '40px';
            container.style.height = '50px';
            const event = new UIEvent('resize');
            window.dispatchEvent(event);
            clock.tick();

            expect(client._display.autoscale).to.have.been.calledOnce;
            expect(client._display.autoscale).to.have.been.calledWith(40, 50);
        });

        it('should update the scaling when the remote session resizes', function () {
            // Simple ExtendedDesktopSize FBU message
            const incoming = [ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0xff, 0x00, 0xff, 0xff, 0xff, 0xfe, 0xcc,
                               0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff,
                               0x00, 0x00, 0x00, 0x00 ];

            sinon.spy(client._display, "autoscale");

            client._sock._websocket._receiveData(new Uint8Array(incoming));

            expect(client._display.autoscale).to.have.been.calledOnce;
            expect(client._display.autoscale).to.have.been.calledWith(70, 80);
        });

        it('should not update the display scale factor if not scaling', function () {
            client.scaleViewport = false;

            sinon.spy(client._display, "autoscale");

            container.style.width = '40px';
            container.style.height = '50px';
            const event = new UIEvent('resize');
            window.dispatchEvent(event);
            clock.tick();

            expect(client._display.autoscale).to.not.have.been.called;
        });
    });

    describe('Remote resize', function () {
        let client;
        beforeEach(function () {
            client = makeRFB();
            client._supportsSetDesktopSize = true;
            client.resizeSession = true;
            container.style.width = '70px';
            container.style.height = '80px';
            sinon.spy(RFB.messages, "setDesktopSize");
        });

        afterEach(function () {
            RFB.messages.setDesktopSize.restore();
        });

        it('should only request a resize when turned on', function () {
            client.resizeSession = false;
            expect(RFB.messages.setDesktopSize).to.not.have.been.called;
            client.resizeSession = true;
            expect(RFB.messages.setDesktopSize).to.have.been.calledOnce;
        });

        it('should request a resize when initially connecting', function () {
            // Simple ExtendedDesktopSize FBU message
            const incoming = [ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x04, 0x00, 0x04, 0xff, 0xff, 0xfe, 0xcc,
                               0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04,
                               0x00, 0x00, 0x00, 0x00 ];

            // First message should trigger a resize

            client._supportsSetDesktopSize = false;

            client._sock._websocket._receiveData(new Uint8Array(incoming));

            expect(RFB.messages.setDesktopSize).to.have.been.calledOnce;
            expect(RFB.messages.setDesktopSize).to.have.been.calledWith(sinon.match.object, 70, 80, 0, 0);

            RFB.messages.setDesktopSize.resetHistory();

            // Second message should not trigger a resize

            client._sock._websocket._receiveData(new Uint8Array(incoming));

            expect(RFB.messages.setDesktopSize).to.not.have.been.called;
        });

        it('should request a resize when the container resizes', function () {
            container.style.width = '40px';
            container.style.height = '50px';
            const event = new UIEvent('resize');
            window.dispatchEvent(event);
            clock.tick(1000);

            expect(RFB.messages.setDesktopSize).to.have.been.calledOnce;
            expect(RFB.messages.setDesktopSize).to.have.been.calledWith(sinon.match.object, 40, 50, 0, 0);
        });

        it('should not resize until the container size is stable', function () {
            container.style.width = '20px';
            container.style.height = '30px';
            const event1 = new UIEvent('resize');
            window.dispatchEvent(event1);
            clock.tick(400);

            expect(RFB.messages.setDesktopSize).to.not.have.been.called;

            container.style.width = '40px';
            container.style.height = '50px';
            const event2 = new UIEvent('resize');
            window.dispatchEvent(event2);
            clock.tick(400);

            expect(RFB.messages.setDesktopSize).to.not.have.been.called;

            clock.tick(200);

            expect(RFB.messages.setDesktopSize).to.have.been.calledOnce;
            expect(RFB.messages.setDesktopSize).to.have.been.calledWith(sinon.match.object, 40, 50, 0, 0);
        });

        it('should not resize when resize is disabled', function () {
            client._resizeSession = false;

            container.style.width = '40px';
            container.style.height = '50px';
            const event = new UIEvent('resize');
            window.dispatchEvent(event);
            clock.tick(1000);

            expect(RFB.messages.setDesktopSize).to.not.have.been.called;
        });

        it('should not resize when resize is not supported', function () {
            client._supportsSetDesktopSize = false;

            container.style.width = '40px';
            container.style.height = '50px';
            const event = new UIEvent('resize');
            window.dispatchEvent(event);
            clock.tick(1000);

            expect(RFB.messages.setDesktopSize).to.not.have.been.called;
        });

        it('should not resize when in view only mode', function () {
            client._viewOnly = true;

            container.style.width = '40px';
            container.style.height = '50px';
            const event = new UIEvent('resize');
            window.dispatchEvent(event);
            clock.tick(1000);

            expect(RFB.messages.setDesktopSize).to.not.have.been.called;
        });

        it('should not try to override a server resize', function () {
            // Simple ExtendedDesktopSize FBU message
            const incoming = [ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x04, 0x00, 0x04, 0xff, 0xff, 0xfe, 0xcc,
                               0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04,
                               0x00, 0x00, 0x00, 0x00 ];

            client._sock._websocket._receiveData(new Uint8Array(incoming));

            expect(RFB.messages.setDesktopSize).to.not.have.been.called;
        });
    });

    describe('Misc Internals', function () {
        describe('#_fail', function () {
            let client;
            beforeEach(function () {
                client = makeRFB();
            });

            it('should close the WebSocket connection', function () {
                sinon.spy(client._sock, 'close');
                client._fail();
                expect(client._sock.close).to.have.been.calledOnce;
            });

            it('should transition to disconnected', function () {
                sinon.spy(client, '_updateConnectionState');
                client._fail();
                this.clock.tick(2000);
                expect(client._updateConnectionState).to.have.been.called;
                expect(client._rfbConnectionState).to.equal('disconnected');
            });

            it('should set clean_disconnect variable', function () {
                client._rfbCleanDisconnect = true;
                client._rfbConnectionState = 'connected';
                client._fail();
                expect(client._rfbCleanDisconnect).to.be.false;
            });

            it('should result in disconnect event with clean set to false', function () {
                client._rfbConnectionState = 'connected';
                const spy = sinon.spy();
                client.addEventListener("disconnect", spy);
                client._fail();
                this.clock.tick(2000);
                expect(spy).to.have.been.calledOnce;
                expect(spy.args[0][0].detail.clean).to.be.false;
            });

        });
    });

    describe('Protocol Initialization States', function () {
        let client;
        beforeEach(function () {
            client = makeRFB();
            client._rfbConnectionState = 'connecting';
        });

        describe('ProtocolVersion', function () {
            function sendVer(ver, client) {
                const arr = new Uint8Array(12);
                for (let i = 0; i < ver.length; i++) {
                    arr[i+4] = ver.charCodeAt(i);
                }
                arr[0] = 'R'; arr[1] = 'F'; arr[2] = 'B'; arr[3] = ' ';
                arr[11] = '\n';
                client._sock._websocket._receiveData(arr);
            }

            describe('version parsing', function () {
                it('should interpret version 003.003 as version 3.3', function () {
                    sendVer('003.003', client);
                    expect(client._rfbVersion).to.equal(3.3);
                });

                it('should interpret version 003.006 as version 3.3', function () {
                    sendVer('003.006', client);
                    expect(client._rfbVersion).to.equal(3.3);
                });

                it('should interpret version 003.889 as version 3.3', function () {
                    sendVer('003.889', client);
                    expect(client._rfbVersion).to.equal(3.3);
                });

                it('should interpret version 003.007 as version 3.7', function () {
                    sendVer('003.007', client);
                    expect(client._rfbVersion).to.equal(3.7);
                });

                it('should interpret version 003.008 as version 3.8', function () {
                    sendVer('003.008', client);
                    expect(client._rfbVersion).to.equal(3.8);
                });

                it('should interpret version 004.000 as version 3.8', function () {
                    sendVer('004.000', client);
                    expect(client._rfbVersion).to.equal(3.8);
                });

                it('should interpret version 004.001 as version 3.8', function () {
                    sendVer('004.001', client);
                    expect(client._rfbVersion).to.equal(3.8);
                });

                it('should interpret version 005.000 as version 3.8', function () {
                    sendVer('005.000', client);
                    expect(client._rfbVersion).to.equal(3.8);
                });

                it('should fail on an invalid version', function () {
                    sinon.spy(client, "_fail");
                    sendVer('002.000', client);
                    expect(client._fail).to.have.been.calledOnce;
                });
            });

            it('should send back the interpreted version', function () {
                sendVer('004.000', client);

                const expectedStr = 'RFB 003.008\n';
                const expected = [];
                for (let i = 0; i < expectedStr.length; i++) {
                    expected[i] = expectedStr.charCodeAt(i);
                }

                expect(client._sock).to.have.sent(new Uint8Array(expected));
            });

            it('should transition to the Security state on successful negotiation', function () {
                sendVer('003.008', client);
                expect(client._rfbInitState).to.equal('Security');
            });

            describe('Repeater', function () {
                beforeEach(function () {
                    client = makeRFB('wss://host:8675', { repeaterID: "12345" });
                    client._rfbConnectionState = 'connecting';
                });

                it('should interpret version 000.000 as a repeater', function () {
                    sendVer('000.000', client);
                    expect(client._rfbVersion).to.equal(0);

                    const sentData = client._sock._websocket._getSentData();
                    expect(new Uint8Array(sentData.buffer, 0, 9)).to.array.equal(new Uint8Array([73, 68, 58, 49, 50, 51, 52, 53, 0]));
                    expect(sentData).to.have.length(250);
                });

                it('should handle two step repeater negotiation', function () {
                    sendVer('000.000', client);
                    sendVer('003.008', client);
                    expect(client._rfbVersion).to.equal(3.8);
                });
            });
        });

        describe('Security', function () {
            beforeEach(function () {
                client._rfbInitState = 'Security';
            });

            it('should simply receive the auth scheme when for versions < 3.7', function () {
                client._rfbVersion = 3.6;
                const authSchemeRaw = [1, 2, 3, 4];
                const authScheme = (authSchemeRaw[0] << 24) + (authSchemeRaw[1] << 16) +
                                  (authSchemeRaw[2] << 8) + authSchemeRaw[3];
                client._sock._websocket._receiveData(new Uint8Array(authSchemeRaw));
                expect(client._rfbAuthScheme).to.equal(authScheme);
            });

            it('should prefer no authentication is possible', function () {
                client._rfbVersion = 3.7;
                const authSchemes = [2, 1, 3];
                client._sock._websocket._receiveData(new Uint8Array(authSchemes));
                expect(client._rfbAuthScheme).to.equal(1);
                expect(client._sock).to.have.sent(new Uint8Array([1, 1]));
            });

            it('should choose for the most prefered scheme possible for versions >= 3.7', function () {
                client._rfbVersion = 3.7;
                const authSchemes = [2, 22, 16];
                client._sock._websocket._receiveData(new Uint8Array(authSchemes));
                expect(client._rfbAuthScheme).to.equal(22);
                expect(client._sock).to.have.sent(new Uint8Array([22]));
            });

            it('should fail if there are no supported schemes for versions >= 3.7', function () {
                sinon.spy(client, "_fail");
                client._rfbVersion = 3.7;
                const authSchemes = [1, 32];
                client._sock._websocket._receiveData(new Uint8Array(authSchemes));
                expect(client._fail).to.have.been.calledOnce;
            });

            it('should fail with the appropriate message if no types are sent for versions >= 3.7', function () {
                client._rfbVersion = 3.7;
                const failureData = [0, 0, 0, 0, 6, 119, 104, 111, 111, 112, 115];
                sinon.spy(client, '_fail');
                client._sock._websocket._receiveData(new Uint8Array(failureData));

                expect(client._fail).to.have.been.calledOnce;
                expect(client._fail).to.have.been.calledWith(
                    'Security negotiation failed on no security types (reason: whoops)');
            });

            it('should transition to the Authentication state and continue on successful negotiation', function () {
                client._rfbVersion = 3.7;
                const authSchemes = [1, 1];
                client._negotiateAuthentication = sinon.spy();
                client._sock._websocket._receiveData(new Uint8Array(authSchemes));
                expect(client._rfbInitState).to.equal('Authentication');
                expect(client._negotiateAuthentication).to.have.been.calledOnce;
            });
        });

        describe('Authentication', function () {
            beforeEach(function () {
                client._rfbInitState = 'Security';
            });

            function sendSecurity(type, cl) {
                cl._sock._websocket._receiveData(new Uint8Array([1, type]));
            }

            it('should fail on auth scheme 0 (pre 3.7) with the given message', function () {
                client._rfbVersion = 3.6;
                const errMsg = "Whoopsies";
                const data = [0, 0, 0, 0];
                const errLen = errMsg.length;
                push32(data, errLen);
                for (let i = 0; i < errLen; i++) {
                    data.push(errMsg.charCodeAt(i));
                }

                sinon.spy(client, '_fail');
                client._sock._websocket._receiveData(new Uint8Array(data));
                expect(client._fail).to.have.been.calledWith(
                    'Security negotiation failed on authentication scheme (reason: Whoopsies)');
            });

            it('should transition straight to SecurityResult on "no auth" (1) for versions >= 3.8', function () {
                client._rfbVersion = 3.8;
                sendSecurity(1, client);
                expect(client._rfbInitState).to.equal('SecurityResult');
            });

            it('should transition straight to ServerInitialisation on "no auth" for versions < 3.8', function () {
                client._rfbVersion = 3.7;
                sendSecurity(1, client);
                expect(client._rfbInitState).to.equal('ServerInitialisation');
            });

            it('should fail on an unknown auth scheme', function () {
                sinon.spy(client, "_fail");
                client._rfbVersion = 3.8;
                sendSecurity(57, client);
                expect(client._fail).to.have.been.calledOnce;
            });

            describe('VNC Authentication (type 2) Handler', function () {
                beforeEach(function () {
                    client._rfbInitState = 'Security';
                    client._rfbVersion = 3.8;
                });

                it('should fire the credentialsrequired event if missing a password', function () {
                    const spy = sinon.spy();
                    client.addEventListener("credentialsrequired", spy);
                    sendSecurity(2, client);

                    const challenge = [];
                    for (let i = 0; i < 16; i++) { challenge[i] = i; }
                    client._sock._websocket._receiveData(new Uint8Array(challenge));

                    expect(client._rfbCredentials).to.be.empty;
                    expect(spy).to.have.been.calledOnce;
                    expect(spy.args[0][0].detail.types).to.have.members(["password"]);
                });

                it('should encrypt the password with DES and then send it back', function () {
                    client._rfbCredentials = { password: 'passwd' };
                    sendSecurity(2, client);
                    client._sock._websocket._getSentData(); // skip the choice of auth reply

                    const challenge = [];
                    for (let i = 0; i < 16; i++) { challenge[i] = i; }
                    client._sock._websocket._receiveData(new Uint8Array(challenge));

                    const desPass = RFB.genDES('passwd', challenge);
                    expect(client._sock).to.have.sent(new Uint8Array(desPass));
                });

                it('should transition to SecurityResult immediately after sending the password', function () {
                    client._rfbCredentials = { password: 'passwd' };
                    sendSecurity(2, client);

                    const challenge = [];
                    for (let i = 0; i < 16; i++) { challenge[i] = i; }
                    client._sock._websocket._receiveData(new Uint8Array(challenge));

                    expect(client._rfbInitState).to.equal('SecurityResult');
                });
            });

            describe('XVP Authentication (type 22) Handler', function () {
                beforeEach(function () {
                    client._rfbInitState = 'Security';
                    client._rfbVersion = 3.8;
                });

                it('should fall through to standard VNC authentication upon completion', function () {
                    client._rfbCredentials = { username: 'user',
                                               target: 'target',
                                               password: 'password' };
                    client._negotiateStdVNCAuth = sinon.spy();
                    sendSecurity(22, client);
                    expect(client._negotiateStdVNCAuth).to.have.been.calledOnce;
                });

                it('should fire the credentialsrequired event if all credentials are missing', function () {
                    const spy = sinon.spy();
                    client.addEventListener("credentialsrequired", spy);
                    client._rfbCredentials = {};
                    sendSecurity(22, client);

                    expect(client._rfbCredentials).to.be.empty;
                    expect(spy).to.have.been.calledOnce;
                    expect(spy.args[0][0].detail.types).to.have.members(["username", "password", "target"]);
                });

                it('should fire the credentialsrequired event if some credentials are missing', function () {
                    const spy = sinon.spy();
                    client.addEventListener("credentialsrequired", spy);
                    client._rfbCredentials = { username: 'user',
                                               target: 'target' };
                    sendSecurity(22, client);

                    expect(spy).to.have.been.calledOnce;
                    expect(spy.args[0][0].detail.types).to.have.members(["username", "password", "target"]);
                });

                it('should send user and target separately', function () {
                    client._rfbCredentials = { username: 'user',
                                               target: 'target',
                                               password: 'password' };
                    client._negotiateStdVNCAuth = sinon.spy();

                    sendSecurity(22, client);

                    const expected = [22, 4, 6]; // auth selection, len user, len target
                    for (let i = 0; i < 10; i++) { expected[i+3] = 'usertarget'.charCodeAt(i); }

                    expect(client._sock).to.have.sent(new Uint8Array(expected));
                });
            });

            describe('TightVNC Authentication (type 16) Handler', function () {
                beforeEach(function () {
                    client._rfbInitState = 'Security';
                    client._rfbVersion = 3.8;
                    sendSecurity(16, client);
                    client._sock._websocket._getSentData();  // skip the security reply
                });

                function sendNumStrPairs(pairs, client) {
                    const data = [];
                    push32(data, pairs.length);

                    for (let i = 0; i < pairs.length; i++) {
                        push32(data, pairs[i][0]);
                        for (let j = 0; j < 4; j++) {
                            data.push(pairs[i][1].charCodeAt(j));
                        }
                        for (let j = 0; j < 8; j++) {
                            data.push(pairs[i][2].charCodeAt(j));
                        }
                    }

                    client._sock._websocket._receiveData(new Uint8Array(data));
                }

                it('should skip tunnel negotiation if no tunnels are requested', function () {
                    client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 0]));
                    expect(client._rfbTightVNC).to.be.true;
                });

                it('should fail if no supported tunnels are listed', function () {
                    sinon.spy(client, "_fail");
                    sendNumStrPairs([[123, 'OTHR', 'SOMETHNG']], client);
                    expect(client._fail).to.have.been.calledOnce;
                });

                it('should choose the notunnel tunnel type', function () {
                    sendNumStrPairs([[0, 'TGHT', 'NOTUNNEL'], [123, 'OTHR', 'SOMETHNG']], client);
                    expect(client._sock).to.have.sent(new Uint8Array([0, 0, 0, 0]));
                });

                it('should choose the notunnel tunnel type for Siemens devices', function () {
                    sendNumStrPairs([[1, 'SICR', 'SCHANNEL'], [2, 'SICR', 'SCHANLPW']], client);
                    expect(client._sock).to.have.sent(new Uint8Array([0, 0, 0, 0]));
                });

                it('should continue to sub-auth negotiation after tunnel negotiation', function () {
                    sendNumStrPairs([[0, 'TGHT', 'NOTUNNEL']], client);
                    client._sock._websocket._getSentData();  // skip the tunnel choice here
                    sendNumStrPairs([[1, 'STDV', 'NOAUTH__']], client);
                    expect(client._sock).to.have.sent(new Uint8Array([0, 0, 0, 1]));
                    expect(client._rfbInitState).to.equal('SecurityResult');
                });

                /*it('should attempt to use VNC auth over no auth when possible', function () {
                    client._rfbTightVNC = true;
                    client._negotiateStdVNCAuth = sinon.spy();
                    sendNumStrPairs([[1, 'STDV', 'NOAUTH__'], [2, 'STDV', 'VNCAUTH_']], client);
                    expect(client._sock).to.have.sent([0, 0, 0, 1]);
                    expect(client._negotiateStdVNCAuth).to.have.been.calledOnce;
                    expect(client._rfbAuthScheme).to.equal(2);
                });*/ // while this would make sense, the original code doesn't actually do this

                it('should accept the "no auth" auth type and transition to SecurityResult', function () {
                    client._rfbTightVNC = true;
                    sendNumStrPairs([[1, 'STDV', 'NOAUTH__']], client);
                    expect(client._sock).to.have.sent(new Uint8Array([0, 0, 0, 1]));
                    expect(client._rfbInitState).to.equal('SecurityResult');
                });

                it('should accept VNC authentication and transition to that', function () {
                    client._rfbTightVNC = true;
                    client._negotiateStdVNCAuth = sinon.spy();
                    sendNumStrPairs([[2, 'STDV', 'VNCAUTH__']], client);
                    expect(client._sock).to.have.sent(new Uint8Array([0, 0, 0, 2]));
                    expect(client._negotiateStdVNCAuth).to.have.been.calledOnce;
                    expect(client._rfbAuthScheme).to.equal(2);
                });

                it('should fail if there are no supported auth types', function () {
                    sinon.spy(client, "_fail");
                    client._rfbTightVNC = true;
                    sendNumStrPairs([[23, 'stdv', 'badval__']], client);
                    expect(client._fail).to.have.been.calledOnce;
                });
            });

            describe('VeNCrypt Authentication (type 19) Handler', function () {
                beforeEach(function () {
                    client._rfbInitState = 'Security';
                    client._rfbVersion = 3.8;
                    sendSecurity(19, client);
                    expect(client._sock).to.have.sent(new Uint8Array([19]));
                });

                it('should fail with non-0.2 versions', function () {
                    sinon.spy(client, "_fail");
                    client._sock._websocket._receiveData(new Uint8Array([0, 1]));
                    expect(client._fail).to.have.been.calledOnce;
                });

                it('should fail if the Plain authentication is not present', function () {
                    // VeNCrypt version
                    client._sock._websocket._receiveData(new Uint8Array([0, 2]));
                    expect(client._sock).to.have.sent(new Uint8Array([0, 2]));
                    // Server ACK.
                    client._sock._websocket._receiveData(new Uint8Array([0]));
                    // Subtype list, only list subtype 1.
                    sinon.spy(client, "_fail");
                    client._sock._websocket._receiveData(new Uint8Array([1, 0, 0, 0, 1]));
                    expect(client._fail).to.have.been.calledOnce;
                });

                it('should support Plain authentication', function () {
                    client._rfbCredentials = { username: 'username', password: 'password' };
                    // VeNCrypt version
                    client._sock._websocket._receiveData(new Uint8Array([0, 2]));
                    expect(client._sock).to.have.sent(new Uint8Array([0, 2]));
                    // Server ACK.
                    client._sock._websocket._receiveData(new Uint8Array([0]));
                    // Subtype list.
                    client._sock._websocket._receiveData(new Uint8Array([1, 0, 0, 1, 0]));

                    const expectedResponse = [];
                    push32(expectedResponse, 256); // Chosen subtype.
                    push32(expectedResponse, client._rfbCredentials.username.length);
                    push32(expectedResponse, client._rfbCredentials.password.length);
                    pushString(expectedResponse, client._rfbCredentials.username);
                    pushString(expectedResponse, client._rfbCredentials.password);
                    expect(client._sock).to.have.sent(new Uint8Array(expectedResponse));

                    client._initMsg = sinon.spy();
                    client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 0]));
                    expect(client._initMsg).to.have.been.called;
                });

                it('should support Plain authentication with an empty password', function () {
                    client._rfbCredentials = { username: 'username', password: '' };
                    // VeNCrypt version
                    client._sock._websocket._receiveData(new Uint8Array([0, 2]));
                    expect(client._sock).to.have.sent(new Uint8Array([0, 2]));
                    // Server ACK.
                    client._sock._websocket._receiveData(new Uint8Array([0]));
                    // Subtype list.
                    client._sock._websocket._receiveData(new Uint8Array([1, 0, 0, 1, 0]));

                    const expectedResponse = [];
                    push32(expectedResponse, 256); // Chosen subtype.
                    push32(expectedResponse, client._rfbCredentials.username.length);
                    push32(expectedResponse, client._rfbCredentials.password.length);
                    pushString(expectedResponse, client._rfbCredentials.username);
                    pushString(expectedResponse, client._rfbCredentials.password);
                    expect(client._sock).to.have.sent(new Uint8Array(expectedResponse));

                    client._initMsg = sinon.spy();
                    client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 0]));
                    expect(client._initMsg).to.have.been.called;
                });

                it('should support Plain authentication with a very long username and password', function () {
                    client._rfbCredentials = { username: 'a'.repeat(300), password: 'a'.repeat(300) };
                    // VeNCrypt version
                    client._sock._websocket._receiveData(new Uint8Array([0, 2]));
                    expect(client._sock).to.have.sent(new Uint8Array([0, 2]));
                    // Server ACK.
                    client._sock._websocket._receiveData(new Uint8Array([0]));
                    // Subtype list.
                    client._sock._websocket._receiveData(new Uint8Array([1, 0, 0, 1, 0]));

                    const expectedResponse = [];
                    push32(expectedResponse, 256); // Chosen subtype.
                    push32(expectedResponse, client._rfbCredentials.username.length);
                    push32(expectedResponse, client._rfbCredentials.password.length);
                    pushString(expectedResponse, client._rfbCredentials.username);
                    pushString(expectedResponse, client._rfbCredentials.password);
                    expect(client._sock).to.have.sent(new Uint8Array(expectedResponse));

                    client._initMsg = sinon.spy();
                    client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 0]));
                    expect(client._initMsg).to.have.been.called;
                });
            });
        });

        describe('SecurityResult', function () {
            beforeEach(function () {
                client._rfbInitState = 'SecurityResult';
            });

            it('should fall through to ServerInitialisation on a response code of 0', function () {
                client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 0]));
                expect(client._rfbInitState).to.equal('ServerInitialisation');
            });

            it('should fail on an error code of 1 with the given message for versions >= 3.8', function () {
                client._rfbVersion = 3.8;
                sinon.spy(client, '_fail');
                const failureData = [0, 0, 0, 1, 0, 0, 0, 6, 119, 104, 111, 111, 112, 115];
                client._sock._websocket._receiveData(new Uint8Array(failureData));
                expect(client._fail).to.have.been.calledWith(
                    'Security negotiation failed on security result (reason: whoops)');
            });

            it('should fail on an error code of 1 with a standard message for version < 3.8', function () {
                sinon.spy(client, '_fail');
                client._rfbVersion = 3.7;
                client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 1]));
                expect(client._fail).to.have.been.calledWith(
                    'Security handshake failed');
            });

            it('should result in securityfailure event when receiving a non zero status', function () {
                const spy = sinon.spy();
                client.addEventListener("securityfailure", spy);
                client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 2]));
                expect(spy).to.have.been.calledOnce;
                expect(spy.args[0][0].detail.status).to.equal(2);
            });

            it('should include reason when provided in securityfailure event', function () {
                client._rfbVersion = 3.8;
                const spy = sinon.spy();
                client.addEventListener("securityfailure", spy);
                const failureData = [0, 0, 0, 1, 0, 0, 0, 12, 115, 117, 99, 104,
                                     32, 102, 97, 105, 108, 117, 114, 101];
                client._sock._websocket._receiveData(new Uint8Array(failureData));
                expect(spy.args[0][0].detail.status).to.equal(1);
                expect(spy.args[0][0].detail.reason).to.equal('such failure');
            });

            it('should not include reason when length is zero in securityfailure event', function () {
                client._rfbVersion = 3.9;
                const spy = sinon.spy();
                client.addEventListener("securityfailure", spy);
                const failureData = [0, 0, 0, 1, 0, 0, 0, 0];
                client._sock._websocket._receiveData(new Uint8Array(failureData));
                expect(spy.args[0][0].detail.status).to.equal(1);
                expect('reason' in spy.args[0][0].detail).to.be.false;
            });

            it('should not include reason in securityfailure event for version < 3.8', function () {
                client._rfbVersion = 3.6;
                const spy = sinon.spy();
                client.addEventListener("securityfailure", spy);
                client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 2]));
                expect(spy.args[0][0].detail.status).to.equal(2);
                expect('reason' in spy.args[0][0].detail).to.be.false;
            });
        });

        describe('ClientInitialisation', function () {
            it('should transition to the ServerInitialisation state', function () {
                const client = makeRFB();
                client._rfbConnectionState = 'connecting';
                client._rfbInitState = 'SecurityResult';
                client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 0]));
                expect(client._rfbInitState).to.equal('ServerInitialisation');
            });

            it('should send 1 if we are in shared mode', function () {
                const client = makeRFB('wss://host:8675', { shared: true });
                client._rfbConnectionState = 'connecting';
                client._rfbInitState = 'SecurityResult';
                client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 0]));
                expect(client._sock).to.have.sent(new Uint8Array([1]));
            });

            it('should send 0 if we are not in shared mode', function () {
                const client = makeRFB('wss://host:8675', { shared: false });
                client._rfbConnectionState = 'connecting';
                client._rfbInitState = 'SecurityResult';
                client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 0]));
                expect(client._sock).to.have.sent(new Uint8Array([0]));
            });
        });

        describe('ServerInitialisation', function () {
            beforeEach(function () {
                client._rfbInitState = 'ServerInitialisation';
            });

            function sendServerInit(opts, client) {
                const fullOpts = { width: 10, height: 12, bpp: 24, depth: 24, bigEndian: 0,
                                   trueColor: 1, redMax: 255, greenMax: 255, blueMax: 255,
                                   redShift: 16, greenShift: 8, blueShift: 0, name: 'a name' };
                for (let opt in opts) {
                    fullOpts[opt] = opts[opt];
                }
                const data = [];

                push16(data, fullOpts.width);
                push16(data, fullOpts.height);

                data.push(fullOpts.bpp);
                data.push(fullOpts.depth);
                data.push(fullOpts.bigEndian);
                data.push(fullOpts.trueColor);

                push16(data, fullOpts.redMax);
                push16(data, fullOpts.greenMax);
                push16(data, fullOpts.blueMax);
                push8(data, fullOpts.redShift);
                push8(data, fullOpts.greenShift);
                push8(data, fullOpts.blueShift);

                // padding
                push8(data, 0);
                push8(data, 0);
                push8(data, 0);

                client._sock._websocket._receiveData(new Uint8Array(data));

                const nameData = [];
                let nameLen = [];
                pushString(nameData, fullOpts.name);
                push32(nameLen, nameData.length);

                client._sock._websocket._receiveData(new Uint8Array(nameLen));
                client._sock._websocket._receiveData(new Uint8Array(nameData));
            }

            it('should set the framebuffer width and height', function () {
                sendServerInit({ width: 32, height: 84 }, client);
                expect(client._fbWidth).to.equal(32);
                expect(client._fbHeight).to.equal(84);
            });

            // NB(sross): we just warn, not fail, for endian-ness and shifts, so we don't test them

            it('should set the framebuffer name and call the callback', function () {
                const spy = sinon.spy();
                client.addEventListener("desktopname", spy);
                sendServerInit({ name: 'som€ nam€' }, client);

                expect(client._fbName).to.equal('som€ nam€');
                expect(spy).to.have.been.calledOnce;
                expect(spy.args[0][0].detail.name).to.equal('som€ nam€');
            });

            it('should handle the extended init message of the tight encoding', function () {
                // NB(sross): we don't actually do anything with it, so just test that we can
                //            read it w/o throwing an error
                client._rfbTightVNC = true;
                sendServerInit({}, client);

                const tightData = [];
                push16(tightData, 1);
                push16(tightData, 2);
                push16(tightData, 3);
                push16(tightData, 0);
                for (let i = 0; i < 16 + 32 + 48; i++) {
                    tightData.push(i);
                }
                client._sock._websocket._receiveData(new Uint8Array(tightData));

                expect(client._rfbConnectionState).to.equal('connected');
            });

            it('should resize the display', function () {
                sinon.spy(client._display, 'resize');
                sendServerInit({ width: 27, height: 32 }, client);

                expect(client._display.resize).to.have.been.calledOnce;
                expect(client._display.resize).to.have.been.calledWith(27, 32);
            });

            it('should grab the keyboard', function () {
                sinon.spy(client._keyboard, 'grab');
                sendServerInit({}, client);
                expect(client._keyboard.grab).to.have.been.calledOnce;
            });

            describe('Initial Update Request', function () {
                beforeEach(function () {
                    sinon.spy(RFB.messages, "pixelFormat");
                    sinon.spy(RFB.messages, "clientEncodings");
                    sinon.spy(RFB.messages, "fbUpdateRequest");
                });

                afterEach(function () {
                    RFB.messages.pixelFormat.restore();
                    RFB.messages.clientEncodings.restore();
                    RFB.messages.fbUpdateRequest.restore();
                });

                // TODO(directxman12): test the various options in this configuration matrix
                it('should reply with the pixel format, client encodings, and initial update request', function () {
                    sendServerInit({ width: 27, height: 32 }, client);

                    expect(RFB.messages.pixelFormat).to.have.been.calledOnce;
                    expect(RFB.messages.pixelFormat).to.have.been.calledWith(client._sock, 24, true);
                    expect(RFB.messages.pixelFormat).to.have.been.calledBefore(RFB.messages.clientEncodings);
                    expect(RFB.messages.clientEncodings).to.have.been.calledOnce;
                    expect(RFB.messages.clientEncodings.getCall(0).args[1]).to.include(encodings.encodingTight);
                    expect(RFB.messages.clientEncodings).to.have.been.calledBefore(RFB.messages.fbUpdateRequest);
                    expect(RFB.messages.fbUpdateRequest).to.have.been.calledOnce;
                    expect(RFB.messages.fbUpdateRequest).to.have.been.calledWith(client._sock, false, 0, 0, 27, 32);
                });

                it('should reply with restricted settings for Intel AMT servers', function () {
                    sendServerInit({ width: 27, height: 32, name: "Intel(r) AMT KVM"}, client);

                    expect(RFB.messages.pixelFormat).to.have.been.calledOnce;
                    expect(RFB.messages.pixelFormat).to.have.been.calledWith(client._sock, 8, true);
                    expect(RFB.messages.pixelFormat).to.have.been.calledBefore(RFB.messages.clientEncodings);
                    expect(RFB.messages.clientEncodings).to.have.been.calledOnce;
                    expect(RFB.messages.clientEncodings.getCall(0).args[1]).to.not.include(encodings.encodingTight);
                    expect(RFB.messages.clientEncodings.getCall(0).args[1]).to.not.include(encodings.encodingHextile);
                    expect(RFB.messages.clientEncodings).to.have.been.calledBefore(RFB.messages.fbUpdateRequest);
                    expect(RFB.messages.fbUpdateRequest).to.have.been.calledOnce;
                    expect(RFB.messages.fbUpdateRequest).to.have.been.calledWith(client._sock, false, 0, 0, 27, 32);
                });
            });

            it('should send the "connect" event', function () {
                let spy = sinon.spy();
                client.addEventListener('connect', spy);
                sendServerInit({}, client);
                expect(spy).to.have.been.calledOnce;
            });
        });
    });

    describe('Protocol Message Processing After Completing Initialization', function () {
        let client;

        beforeEach(function () {
            client = makeRFB();
            client._fbName = 'some device';
            client._fbWidth = 640;
            client._fbHeight = 20;
        });

        describe('Framebuffer Update Handling', function () {
            function sendFbuMsg(rectInfo, rectData, client, rectCnt) {
                let data = [];

                if (!rectCnt || rectCnt > -1) {
                    // header
                    data.push(0);  // msg type
                    data.push(0);  // padding
                    push16(data, rectCnt || rectData.length);
                }

                for (let i = 0; i < rectData.length; i++) {
                    if (rectInfo[i]) {
                        push16(data, rectInfo[i].x);
                        push16(data, rectInfo[i].y);
                        push16(data, rectInfo[i].width);
                        push16(data, rectInfo[i].height);
                        push32(data, rectInfo[i].encoding);
                    }
                    data = data.concat(rectData[i]);
                }

                client._sock._websocket._receiveData(new Uint8Array(data));
            }

            it('should send an update request if there is sufficient data', function () {
                const expectedMsg = {_sQ: new Uint8Array(10), _sQlen: 0, flush: () => {}};
                RFB.messages.fbUpdateRequest(expectedMsg, true, 0, 0, 640, 20);

                client._framebufferUpdate = () => true;
                client._sock._websocket._receiveData(new Uint8Array([0]));

                expect(client._sock).to.have.sent(expectedMsg._sQ);
            });

            it('should not send an update request if we need more data', function () {
                client._sock._websocket._receiveData(new Uint8Array([0]));
                expect(client._sock._websocket._getSentData()).to.have.length(0);
            });

            it('should resume receiving an update if we previously did not have enough data', function () {
                const expectedMsg = {_sQ: new Uint8Array(10), _sQlen: 0, flush: () => {}};
                RFB.messages.fbUpdateRequest(expectedMsg, true, 0, 0, 640, 20);

                // just enough to set FBU.rects
                client._sock._websocket._receiveData(new Uint8Array([0, 0, 0, 3]));
                expect(client._sock._websocket._getSentData()).to.have.length(0);

                client._framebufferUpdate = function () { this._sock.rQskipBytes(1); return true; };  // we magically have enough data
                // 247 should *not* be used as the message type here
                client._sock._websocket._receiveData(new Uint8Array([247]));
                expect(client._sock).to.have.sent(expectedMsg._sQ);
            });

            it('should not send a request in continuous updates mode', function () {
                client._enabledContinuousUpdates = true;
                client._framebufferUpdate = () => true;
                client._sock._websocket._receiveData(new Uint8Array([0]));

                expect(client._sock._websocket._getSentData()).to.have.length(0);
            });

            it('should fail on an unsupported encoding', function () {
                sinon.spy(client, "_fail");
                const rectInfo = { x: 8, y: 11, width: 27, height: 32, encoding: 234 };
                sendFbuMsg([rectInfo], [[]], client);
                expect(client._fail).to.have.been.calledOnce;
            });

            describe('Message Encoding Handlers', function () {
                beforeEach(function () {
                    // a really small frame
                    client._fbWidth = 4;
                    client._fbHeight = 4;
                    client._fbDepth = 24;
                    client._display.resize(4, 4);
                });

                it('should handle the DesktopSize pseduo-encoding', function () {
                    sinon.spy(client._display, 'resize');
                    sendFbuMsg([{ x: 0, y: 0, width: 20, height: 50, encoding: -223 }], [[]], client);

                    expect(client._fbWidth).to.equal(20);
                    expect(client._fbHeight).to.equal(50);

                    expect(client._display.resize).to.have.been.calledOnce;
                    expect(client._display.resize).to.have.been.calledWith(20, 50);
                });

                describe('the ExtendedDesktopSize pseudo-encoding handler', function () {
                    beforeEach(function () {
                        // a really small frame
                        client._fbWidth = 4;
                        client._fbHeight = 4;
                        client._display.resize(4, 4);
                        sinon.spy(client._display, 'resize');
                    });

                    function makeScreenData(nrOfScreens) {
                        const data = [];
                        push8(data, nrOfScreens);   // number-of-screens
                        push8(data, 0);               // padding
                        push16(data, 0);              // padding
                        for (let i=0; i<nrOfScreens; i += 1) {
                            push32(data, 0);  // id
                            push16(data, 0);  // x-position
                            push16(data, 0);  // y-position
                            push16(data, 20); // width
                            push16(data, 50); // height
                            push32(data, 0);  // flags
                        }
                        return data;
                    }

                    it('should handle a resize requested by this client', function () {
                        const reasonForChange = 1; // requested by this client
                        const statusCode      = 0; // No error

                        sendFbuMsg([{ x: reasonForChange, y: statusCode,
                                      width: 20, height: 50, encoding: -308 }],
                                   makeScreenData(1), client);

                        expect(client._fbWidth).to.equal(20);
                        expect(client._fbHeight).to.equal(50);

                        expect(client._display.resize).to.have.been.calledOnce;
                        expect(client._display.resize).to.have.been.calledWith(20, 50);
                    });

                    it('should handle a resize requested by another client', function () {
                        const reasonForChange = 2; // requested by another client
                        const statusCode      = 0; // No error

                        sendFbuMsg([{ x: reasonForChange, y: statusCode,
                                      width: 20, height: 50, encoding: -308 }],
                                   makeScreenData(1), client);

                        expect(client._fbWidth).to.equal(20);
                        expect(client._fbHeight).to.equal(50);

                        expect(client._display.resize).to.have.been.calledOnce;
                        expect(client._display.resize).to.have.been.calledWith(20, 50);
                    });

                    it('should be able to recieve requests which contain data for multiple screens', function () {
                        const reasonForChange = 2; // requested by another client
                        const statusCode      = 0; // No error

                        sendFbuMsg([{ x: reasonForChange, y: statusCode,
                                      width: 60, height: 50, encoding: -308 }],
                                   makeScreenData(3), client);

                        expect(client._fbWidth).to.equal(60);
                        expect(client._fbHeight).to.equal(50);

                        expect(client._display.resize).to.have.been.calledOnce;
                        expect(client._display.resize).to.have.been.calledWith(60, 50);
                    });

                    it('should not handle a failed request', function () {
                        const reasonForChange = 1; // requested by this client
                        const statusCode      = 1; // Resize is administratively prohibited

                        sendFbuMsg([{ x: reasonForChange, y: statusCode,
                                      width: 20, height: 50, encoding: -308 }],
                                   makeScreenData(1), client);

                        expect(client._fbWidth).to.equal(4);
                        expect(client._fbHeight).to.equal(4);

                        expect(client._display.resize).to.not.have.been.called;
                    });
                });

                describe('the Cursor pseudo-encoding handler', function () {
                    beforeEach(function () {
                        sinon.spy(client._cursor, 'change');
                    });

                    it('should handle a standard cursor', function () {
                        const info = { x: 5, y: 7,
                                       width: 4, height: 4,
                                       encoding: -239};
                        let rect = [];
                        let expected = [];

                        for (let i = 0;i < info.width*info.height;i++) {
                            push32(rect, 0x11223300);
                        }
                        push32(rect, 0xa0a0a0a0);

                        for (let i = 0;i < info.width*info.height/2;i++) {
                            push32(expected, 0x332211ff);
                            push32(expected, 0x33221100);
                        }
                        expected = new Uint8Array(expected);

                        sendFbuMsg([info], [rect], client);

                        expect(client._cursor.change).to.have.been.calledOnce;
                        expect(client._cursor.change).to.have.been.calledWith(expected, 5, 7, 4, 4);
                    });

                    it('should handle an empty cursor', function () {
                        const info = { x: 0, y: 0,
                                       width: 0, height: 0,
                                       encoding: -239};
                        const rect = [];

                        sendFbuMsg([info], [rect], client);

                        expect(client._cursor.change).to.have.been.calledOnce;
                        expect(client._cursor.change).to.have.been.calledWith(new Uint8Array, 0, 0, 0, 0);
                    });

                    it('should handle a transparent cursor', function () {
                        const info = { x: 5, y: 7,
                                       width: 4, height: 4,
                                       encoding: -239};
                        let rect = [];
                        let expected = [];

                        for (let i = 0;i < info.width*info.height;i++) {
                            push32(rect, 0x11223300);
                        }
                        push32(rect, 0x00000000);

                        for (let i = 0;i < info.width*info.height;i++) {
                            push32(expected, 0x33221100);
                        }
                        expected = new Uint8Array(expected);

                        sendFbuMsg([info], [rect], client);

                        expect(client._cursor.change).to.have.been.calledOnce;
                        expect(client._cursor.change).to.have.been.calledWith(expected, 5, 7, 4, 4);
                    });

                    describe('dot for empty cursor', function () {
                        beforeEach(function () {
                            client.showDotCursor = true;
                            // Was called when we enabled dot cursor
                            client._cursor.change.resetHistory();
                        });

                        it('should show a standard cursor', function () {
                            const info = { x: 5, y: 7,
                                           width: 4, height: 4,
                                           encoding: -239};
                            let rect = [];
                            let expected = [];

                            for (let i = 0;i < info.width*info.height;i++) {
                                push32(rect, 0x11223300);
                            }
                            push32(rect, 0xa0a0a0a0);

                            for (let i = 0;i < info.width*info.height/2;i++) {
                                push32(expected, 0x332211ff);
                                push32(expected, 0x33221100);
                            }
                            expected = new Uint8Array(expected);

                            sendFbuMsg([info], [rect], client);

                            expect(client._cursor.change).to.have.been.calledOnce;
                            expect(client._cursor.change).to.have.been.calledWith(expected, 5, 7, 4, 4);
                        });

                        it('should handle an empty cursor', function () {
                            const info = { x: 0, y: 0,
                                           width: 0, height: 0,
                                           encoding: -239};
                            const rect = [];
                            const dot = RFB.cursors.dot;

                            sendFbuMsg([info], [rect], client);

                            expect(client._cursor.change).to.have.been.calledOnce;
                            expect(client._cursor.change).to.have.been.calledWith(dot.rgbaPixels,
                                                                                  dot.hotx,
                                                                                  dot.hoty,
                                                                                  dot.w,
                                                                                  dot.h);
                        });

                        it('should handle a transparent cursor', function () {
                            const info = { x: 5, y: 7,
                                           width: 4, height: 4,
                                           encoding: -239};
                            let rect = [];
                            const dot = RFB.cursors.dot;

                            for (let i = 0;i < info.width*info.height;i++) {
                                push32(rect, 0x11223300);
                            }
                            push32(rect, 0x00000000);

                            sendFbuMsg([info], [rect], client);

                            expect(client._cursor.change).to.have.been.calledOnce;
                            expect(client._cursor.change).to.have.been.calledWith(dot.rgbaPixels,
                                                                                  dot.hotx,
                                                                                  dot.hoty,
                                                                                  dot.w,
                                                                                  dot.h);
                        });
                    });
                });

                describe('the VMware Cursor pseudo-encoding handler', function () {
                    beforeEach(function () {
                        sinon.spy(client._cursor, 'change');
                    });
                    afterEach(function () {
                        client._cursor.change.resetHistory();
                    });

                    it('should handle the VMware cursor pseudo-encoding', function () {
                        let data = [0x00, 0x00, 0xff, 0,
                                    0x00, 0xff, 0x00, 0,
                                    0x00, 0xff, 0x00, 0,
                                    0x00, 0x00, 0xff, 0];
                        let rect = [];
                        push8(rect, 0);
                        push8(rect, 0);

                        //AND-mask
                        for (let i = 0; i < data.length; i++) {
                            push8(rect, data[i]);
                        }
                        //XOR-mask
                        for (let i = 0; i < data.length; i++) {
                            push8(rect, data[i]);
                        }

                        sendFbuMsg([{ x: 0, y: 0, width: 2, height: 2,
                                      encoding: 0x574d5664}],
                                   [rect], client);
                        expect(client._FBU.rects).to.equal(0);
                    });

                    it('should handle insufficient cursor pixel data', function () {

                        // Specified 14x23 pixels for the cursor,
                        // but only send 2x2 pixels worth of data
                        let w = 14;
                        let h = 23;
                        let data = [0x00, 0x00, 0xff, 0,
                                    0x00, 0xff, 0x00, 0];
                        let rect = [];

                        push8(rect, 0);
                        push8(rect, 0);

                        //AND-mask
                        for (let i = 0; i < data.length; i++) {
                            push8(rect, data[i]);
                        }
                        //XOR-mask
                        for (let i = 0; i < data.length; i++) {
                            push8(rect, data[i]);
                        }

                        sendFbuMsg([{ x: 0, y: 0, width: w, height: h,
                                      encoding: 0x574d5664}],
                                   [rect], client);

                        // expect one FBU to remain unhandled
                        expect(client._FBU.rects).to.equal(1);
                    });

                    it('should update the cursor when type is classic', function () {
                        let andMask =
                            [0xff, 0xff, 0xff, 0xff,  //Transparent
                             0xff, 0xff, 0xff, 0xff,  //Transparent
                             0x00, 0x00, 0x00, 0x00,  //Opaque
                             0xff, 0xff, 0xff, 0xff]; //Inverted

                        let xorMask =
                            [0x00, 0x00, 0x00, 0x00,  //Transparent
                             0x00, 0x00, 0x00, 0x00,  //Transparent
                             0x11, 0x22, 0x33, 0x44,  //Opaque
                             0xff, 0xff, 0xff, 0x44]; //Inverted

                        let rect = [];
                        push8(rect, 0); //cursor_type
                        push8(rect, 0); //padding
                        let hotx = 0;
                        let hoty = 0;
                        let w = 2;
                        let h = 2;

                        //AND-mask
                        for (let i = 0; i < andMask.length; i++) {
                            push8(rect, andMask[i]);
                        }
                        //XOR-mask
                        for (let i = 0; i < xorMask.length; i++) {
                            push8(rect, xorMask[i]);
                        }

                        let expectedRgba = [0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00,
                                            0x33, 0x22, 0x11, 0xff,
                                            0x00, 0x00, 0x00, 0xff];

                        sendFbuMsg([{ x: hotx, y: hoty,
                                      width: w, height: h,
                                      encoding: 0x574d5664}],
                                   [rect], client);

                        expect(client._cursor.change)
                            .to.have.been.calledOnce;
                        expect(client._cursor.change)
                            .to.have.been.calledWith(expectedRgba,
                                                     hotx, hoty,
                                                     w, h);
                    });

                    it('should update the cursor when type is alpha', function () {
                        let data = [0xee, 0x55, 0xff, 0x00, // rgba
                                    0x00, 0xff, 0x00, 0xff,
                                    0x00, 0xff, 0x00, 0x22,
                                    0x00, 0xff, 0x00, 0x22,
                                    0x00, 0xff, 0x00, 0x22,
                                    0x00, 0x00, 0xff, 0xee];
                        let rect = [];
                        push8(rect, 1); //cursor_type
                        push8(rect, 0); //padding
                        let hotx = 0;
                        let hoty = 0;
                        let w = 3;
                        let h = 2;

                        for (let i = 0; i < data.length; i++) {
                            push8(rect, data[i]);
                        }

                        let expectedRgba = [0xee, 0x55, 0xff, 0x00,
                                            0x00, 0xff, 0x00, 0xff,
                                            0x00, 0xff, 0x00, 0x22,
                                            0x00, 0xff, 0x00, 0x22,
                                            0x00, 0xff, 0x00, 0x22,
                                            0x00, 0x00, 0xff, 0xee];

                        sendFbuMsg([{ x: hotx, y: hoty,
                                      width: w, height: h,
                                      encoding: 0x574d5664}],
                                   [rect], client);

                        expect(client._cursor.change)
                            .to.have.been.calledOnce;
                        expect(client._cursor.change)
                            .to.have.been.calledWith(expectedRgba,
                                                     hotx, hoty,
                                                     w, h);
                    });

                    it('should not update cursor when incorrect cursor type given', function () {
                        let rect = [];
                        push8(rect, 3); // invalid cursor type
                        push8(rect, 0); // padding

                        client._cursor.change.resetHistory();
                        sendFbuMsg([{ x: 0, y: 0, width: 2, height: 2,
                                      encoding: 0x574d5664}],
                                   [rect], client);

                        expect(client._cursor.change)
                            .to.not.have.been.called;
                    });
                });

                it('should handle the last_rect pseudo-encoding', function () {
                    sendFbuMsg([{ x: 0, y: 0, width: 0, height: 0, encoding: -224}], [[]], client, 100);
                    expect(client._FBU.rects).to.equal(0);
                });

                it('should handle the DesktopName pseudo-encoding', function () {
                    let data = [];
                    push32(data, 13);
                    pushString(data, "som€ nam€");

                    const spy = sinon.spy();
                    client.addEventListener("desktopname", spy);

                    sendFbuMsg([{ x: 0, y: 0, width: 0, height: 0, encoding: -307 }], [data], client);

                    expect(client._fbName).to.equal('som€ nam€');
                    expect(spy).to.have.been.calledOnce;
                    expect(spy.args[0][0].detail.name).to.equal('som€ nam€');
                });
            });
        });

        describe('XVP Message Handling', function () {
            it('should set the XVP version and fire the callback with the version on XVP_INIT', function () {
                const spy = sinon.spy();
                client.addEventListener("capabilities", spy);
                client._sock._websocket._receiveData(new Uint8Array([250, 0, 10, 1]));
                expect(client._rfbXvpVer).to.equal(10);
                expect(spy).to.have.been.calledOnce;
                expect(spy.args[0][0].detail.capabilities.power).to.be.true;
                expect(client.capabilities.power).to.be.true;
            });

            it('should fail on unknown XVP message types', function () {
                sinon.spy(client, "_fail");
                client._sock._websocket._receiveData(new Uint8Array([250, 0, 10, 237]));
                expect(client._fail).to.have.been.calledOnce;
            });
        });

        describe('Normal Clipboard Handling Receive', function () {
            it('should fire the clipboard callback with the retrieved text on ServerCutText', function () {
                const expectedStr = 'cheese!';
                const data = [3, 0, 0, 0];
                push32(data, expectedStr.length);
                for (let i = 0; i < expectedStr.length; i++) { data.push(expectedStr.charCodeAt(i)); }
                const spy = sinon.spy();
                client.addEventListener("clipboard", spy);

                client._sock._websocket._receiveData(new Uint8Array(data));
                expect(spy).to.have.been.calledOnce;
                expect(spy.args[0][0].detail.text).to.equal(expectedStr);
            });
        });

        describe('Extended clipboard Handling', function () {

            describe('Extended clipboard initialization', function () {
                beforeEach(function () {
                    sinon.spy(RFB.messages, 'extendedClipboardCaps');
                });

                afterEach(function () {
                    RFB.messages.extendedClipboardCaps.restore();
                });

                it('should update capabilities when receiving a Caps message', function () {
                    let data = [3, 0, 0, 0];
                    const flags = [0x1F, 0x00, 0x00, 0x03];
                    let fileSizes = [0x00, 0x00, 0x00, 0x1E,
                                     0x00, 0x00, 0x00, 0x3C];

                    push32(data, toUnsigned32bit(-12));
                    data = data.concat(flags);
                    data = data.concat(fileSizes);
                    client._sock._websocket._receiveData(new Uint8Array(data));

                    // Check that we give an response caps when we receive one
                    expect(RFB.messages.extendedClipboardCaps).to.have.been.calledOnce;

                    // FIXME: Can we avoid checking internal variables?
                    expect(client._clipboardServerCapabilitiesFormats[0]).to.not.equal(true);
                    expect(client._clipboardServerCapabilitiesFormats[1]).to.equal(true);
                    expect(client._clipboardServerCapabilitiesFormats[2]).to.equal(true);
                    expect(client._clipboardServerCapabilitiesActions[(1 << 24)]).to.equal(true);
                });


            });

            describe('Extended Clipboard Handling Receive', function () {

                beforeEach(function () {
                    // Send our capabilities
                    let data = [3, 0, 0, 0];
                    const flags = [0x1F, 0x00, 0x00, 0x01];
                    let fileSizes = [0x00, 0x00, 0x00, 0x1E];

                    push32(data, toUnsigned32bit(-8));
                    data = data.concat(flags);
                    data = data.concat(fileSizes);
                    client._sock._websocket._receiveData(new Uint8Array(data));
                });

                describe('Handle Provide', function () {
                    it('should update clipboard with correct Unicode data from a Provide message', function () {
                        let expectedData = "Aå漢字!";
                        let data = [3, 0, 0, 0];
                        const flags = [0x10, 0x00, 0x00, 0x01];

                        /* The size 10 (utf8 encoded string size) and the
                        string "Aå漢字!" utf8 encoded and deflated. */
                        let deflatedData = [120, 94, 99, 96, 96, 224, 114, 60,
                                            188, 244, 217, 158, 69, 79, 215,
                                            78, 87, 4, 0, 35, 207, 6, 66];

                        // How much data we are sending.
                        push32(data, toUnsigned32bit(-(4 + deflatedData.length)));

                        data = data.concat(flags);
                        data = data.concat(deflatedData);

                        const spy = sinon.spy();
                        client.addEventListener("clipboard", spy);

                        client._sock._websocket._receiveData(new Uint8Array(data));
                        expect(spy).to.have.been.calledOnce;
                        expect(spy.args[0][0].detail.text).to.equal(expectedData);
                        client.removeEventListener("clipboard", spy);
                    });

                    it('should update clipboard with correct escape characters from a Provide message ', function () {
                        let expectedData = "Oh\nmy!";
                        let data = [3, 0, 0, 0];
                        const flags = [0x10, 0x00, 0x00, 0x01];

                        let text = encodeUTF8("Oh\r\nmy!\0");

                        let deflatedText = deflateWithSize(text);

                        // How much data we are sending.
                        push32(data, toUnsigned32bit(-(4 + deflatedText.length)));

                        data = data.concat(flags);

                        let sendData = new Uint8Array(data.length + deflatedText.length);
                        sendData.set(data);
                        sendData.set(deflatedText, data.length);

                        const spy = sinon.spy();
                        client.addEventListener("clipboard", spy);

                        client._sock._websocket._receiveData(sendData);
                        expect(spy).to.have.been.calledOnce;
                        expect(spy.args[0][0].detail.text).to.equal(expectedData);
                        client.removeEventListener("clipboard", spy);
                    });

                    it('should be able to handle large Provide messages', function () {
                        let expectedData = "hello".repeat(100000);
                        let data = [3, 0, 0, 0];
                        const flags = [0x10, 0x00, 0x00, 0x01];

                        let text = encodeUTF8(expectedData + "\0");

                        let deflatedText = deflateWithSize(text);

                        // How much data we are sending.
                        push32(data, toUnsigned32bit(-(4 + deflatedText.length)));

                        data = data.concat(flags);

                        let sendData = new Uint8Array(data.length + deflatedText.length);
                        sendData.set(data);
                        sendData.set(deflatedText, data.length);

                        const spy = sinon.spy();
                        client.addEventListener("clipboard", spy);

                        client._sock._websocket._receiveData(sendData);
                        expect(spy).to.have.been.calledOnce;
                        expect(spy.args[0][0].detail.text).to.equal(expectedData);
                        client.removeEventListener("clipboard", spy);
                    });

                });

                describe('Handle Notify', function () {
                    beforeEach(function () {
                        sinon.spy(RFB.messages, 'extendedClipboardRequest');
                    });

                    afterEach(function () {
                        RFB.messages.extendedClipboardRequest.restore();
                    });

                    it('should make a request with supported formats when receiving a notify message', function () {
                        let data = [3, 0, 0, 0];
                        const flags = [0x08, 0x00, 0x00, 0x07];
                        push32(data, toUnsigned32bit(-4));
                        data = data.concat(flags);
                        let expectedData = [0x01];

                        client._sock._websocket._receiveData(new Uint8Array(data));

                        expect(RFB.messages.extendedClipboardRequest).to.have.been.calledOnce;
                        expect(RFB.messages.extendedClipboardRequest).to.have.been.calledWith(client._sock, expectedData);
                    });
                });

                describe('Handle Peek', function () {
                    beforeEach(function () {
                        sinon.spy(RFB.messages, 'extendedClipboardNotify');
                    });

                    afterEach(function () {
                        RFB.messages.extendedClipboardNotify.restore();
                    });

                    it('should send an empty Notify when receiving a Peek and no excisting clipboard data', function () {
                        let data = [3, 0, 0, 0];
                        const flags = [0x04, 0x00, 0x00, 0x00];
                        push32(data, toUnsigned32bit(-4));
                        data = data.concat(flags);
                        let expectedData = [];

                        client._sock._websocket._receiveData(new Uint8Array(data));

                        expect(RFB.messages.extendedClipboardNotify).to.have.been.calledOnce;
                        expect(RFB.messages.extendedClipboardNotify).to.have.been.calledWith(client._sock, expectedData);
                    });

                    it('should send a Notify message with supported formats when receiving a Peek', function () {
                        let data = [3, 0, 0, 0];
                        const flags = [0x04, 0x00, 0x00, 0x00];
                        push32(data, toUnsigned32bit(-4));
                        data = data.concat(flags);
                        let expectedData = [0x01];

                        // Needed to have clipboard data to read.
                        // This will trigger a call to Notify, reset history
                        client.clipboardPasteFrom("HejHej");
                        RFB.messages.extendedClipboardNotify.resetHistory();

                        client._sock._websocket._receiveData(new Uint8Array(data));

                        expect(RFB.messages.extendedClipboardNotify).to.have.been.calledOnce;
                        expect(RFB.messages.extendedClipboardNotify).to.have.been.calledWith(client._sock, expectedData);
                    });
                });

                describe('Handle Request', function () {
                    beforeEach(function () {
                        sinon.spy(RFB.messages, 'extendedClipboardProvide');
                    });

                    afterEach(function () {
                        RFB.messages.extendedClipboardProvide.restore();
                    });

                    it('should send a Provide message with supported formats when receiving a Request', function () {
                        let data = [3, 0, 0, 0];
                        const flags = [0x02, 0x00, 0x00, 0x01];
                        push32(data, toUnsigned32bit(-4));
                        data = data.concat(flags);
                        let expectedData = [0x01];

                        client.clipboardPasteFrom("HejHej");
                        expect(RFB.messages.extendedClipboardProvide).to.not.have.been.called;

                        client._sock._websocket._receiveData(new Uint8Array(data));

                        expect(RFB.messages.extendedClipboardProvide).to.have.been.calledOnce;
                        expect(RFB.messages.extendedClipboardProvide).to.have.been.calledWith(client._sock, expectedData, ["HejHej"]);
                    });
                });
            });

        });

        it('should fire the bell callback on Bell', function () {
            const spy = sinon.spy();
            client.addEventListener("bell", spy);
            client._sock._websocket._receiveData(new Uint8Array([2]));
            expect(spy).to.have.been.calledOnce;
        });

        it('should respond correctly to ServerFence', function () {
            const expectedMsg = {_sQ: new Uint8Array(16), _sQlen: 0, flush: () => {}};
            const incomingMsg = {_sQ: new Uint8Array(16), _sQlen: 0, flush: () => {}};

            const payload = "foo\x00ab9";

            // ClientFence and ServerFence are identical in structure
            RFB.messages.clientFence(expectedMsg, (1<<0) | (1<<1), payload);
            RFB.messages.clientFence(incomingMsg, 0xffffffff, payload);

            client._sock._websocket._receiveData(incomingMsg._sQ);

            expect(client._sock).to.have.sent(expectedMsg._sQ);

            expectedMsg._sQlen = 0;
            incomingMsg._sQlen = 0;

            RFB.messages.clientFence(expectedMsg, (1<<0), payload);
            RFB.messages.clientFence(incomingMsg, (1<<0) | (1<<31), payload);

            client._sock._websocket._receiveData(incomingMsg._sQ);

            expect(client._sock).to.have.sent(expectedMsg._sQ);
        });

        it('should enable continuous updates on first EndOfContinousUpdates', function () {
            const expectedMsg = {_sQ: new Uint8Array(10), _sQlen: 0, flush: () => {}};

            RFB.messages.enableContinuousUpdates(expectedMsg, true, 0, 0, 640, 20);

            expect(client._enabledContinuousUpdates).to.be.false;

            client._sock._websocket._receiveData(new Uint8Array([150]));

            expect(client._enabledContinuousUpdates).to.be.true;
            expect(client._sock).to.have.sent(expectedMsg._sQ);
        });

        it('should disable continuous updates on subsequent EndOfContinousUpdates', function () {
            client._enabledContinuousUpdates = true;
            client._supportsContinuousUpdates = true;

            client._sock._websocket._receiveData(new Uint8Array([150]));

            expect(client._enabledContinuousUpdates).to.be.false;
        });

        it('should update continuous updates on resize', function () {
            const expectedMsg = {_sQ: new Uint8Array(10), _sQlen: 0, flush: () => {}};
            RFB.messages.enableContinuousUpdates(expectedMsg, true, 0, 0, 90, 700);

            client._resize(450, 160);

            expect(client._sock._websocket._getSentData()).to.have.length(0);

            client._enabledContinuousUpdates = true;

            client._resize(90, 700);

            expect(client._sock).to.have.sent(expectedMsg._sQ);
        });

        it('should fail on an unknown message type', function () {
            sinon.spy(client, "_fail");
            client._sock._websocket._receiveData(new Uint8Array([87]));
            expect(client._fail).to.have.been.calledOnce;
        });
    });

    describe('Asynchronous Events', function () {
        let client;
        let pointerEvent;
        let keyEvent;
        let qemuKeyEvent;

        beforeEach(function () {
            client = makeRFB();
            client._display.resize(100, 100);

            // We need to disable this as focusing the canvas will
            // cause the browser to scoll to it, messing up our
            // client coordinate calculations
            client.focusOnClick = false;

            pointerEvent = sinon.spy(RFB.messages, 'pointerEvent');
            keyEvent = sinon.spy(RFB.messages, 'keyEvent');
            qemuKeyEvent = sinon.spy(RFB.messages, 'QEMUExtendedKeyEvent');
        });

        afterEach(function () {
            pointerEvent.restore();
            keyEvent.restore();
            qemuKeyEvent.restore();
        });

        function elementToClient(x, y) {
            let res = { x: 0, y: 0 };

            let bounds = client._canvas.getBoundingClientRect();

            /*
             * If the canvas is on a fractional position we will calculate
             * a fractional mouse position. But that gets truncated when we
             * send the event, AND the same thing happens in RFB when it
             * generates the PointerEvent message. To compensate for that
             * fact we round the value upwards here.
             */
            res.x = Math.ceil(bounds.left + x);
            res.y = Math.ceil(bounds.top + y);

            return res;
        }

        describe('Mouse Events', function () {
            function sendMouseMoveEvent(x, y) {
                let pos = elementToClient(x, y);
                let ev;

                ev = new MouseEvent('mousemove',
                                    { 'screenX': pos.x + window.screenX,
                                      'screenY': pos.y + window.screenY,
                                      'clientX': pos.x,
                                      'clientY': pos.y });
                client._canvas.dispatchEvent(ev);
            }

            function supportsSendMouseMovementEvent() {
                // Some browsers (like Safari) support the movementX /
                // movementY properties of MouseEvent, but do not allow creation
                // of non-trusted events with those properties.
                let ev;

                ev = new MouseEvent('mousemove',
                                    { 'movementX': 100,
                                      'movementY': 100 });
                return ev.movementX === 100 && ev.movementY === 100;
            }

            function sendMouseMovementEvent(dx, dy) {
                let ev;

                ev = new MouseEvent('mousemove',
                                    { 'movementX': dx,
                                      'movementY': dy });
                client._canvas.dispatchEvent(ev);
            }

            function sendMouseButtonEvent(x, y, down, button) {
                let pos = elementToClient(x, y);
                let ev;

                ev = new MouseEvent(down ? 'mousedown' : 'mouseup',
                                    { 'screenX': pos.x + window.screenX,
                                      'screenY': pos.y + window.screenY,
                                      'clientX': pos.x,
                                      'clientY': pos.y,
                                      'button': button,
                                      'buttons': 1 << button });
                client._canvas.dispatchEvent(ev);
            }

            it('should not send button messages in view-only mode', function () {
                client._viewOnly = true;
                sendMouseButtonEvent(10, 10, true, 0);
                clock.tick(50);
                expect(pointerEvent).to.not.have.been.called;
            });

            it('should not send movement messages in view-only mode', function () {
                client._viewOnly = true;
                sendMouseMoveEvent(10, 10);
                clock.tick(50);
                expect(pointerEvent).to.not.have.been.called;
            });

            it('should handle left mouse button', function () {
                sendMouseButtonEvent(10, 10, true, 0);

                expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                 10, 10, 0x1);
                pointerEvent.resetHistory();

                sendMouseButtonEvent(10, 10, false, 0);

                expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                 10, 10, 0x0);
            });

            it('should handle middle mouse button', function () {
                sendMouseButtonEvent(10, 10, true, 1);

                expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                 10, 10, 0x2);
                pointerEvent.resetHistory();

                sendMouseButtonEvent(10, 10, false, 1);

                expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                 10, 10, 0x0);
            });

            it('should handle right mouse button', function () {
                sendMouseButtonEvent(10, 10, true, 2);

                expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                 10, 10, 0x4);
                pointerEvent.resetHistory();

                sendMouseButtonEvent(10, 10, false, 2);

                expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                 10, 10, 0x0);
            });

            it('should handle multiple mouse buttons', function () {
                sendMouseButtonEvent(10, 10, true, 0);
                sendMouseButtonEvent(10, 10, true, 2);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 0x1);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        10, 10, 0x5);

                pointerEvent.resetHistory();

                sendMouseButtonEvent(10, 10, false, 0);
                sendMouseButtonEvent(10, 10, false, 2);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 0x4);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        10, 10, 0x0);
            });

            it('should handle mouse movement', function () {
                sendMouseMoveEvent(50, 70);
                expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                 50, 70, 0x0);
            });

            it('should handle click and drag', function () {
                sendMouseButtonEvent(10, 10, true, 0);
                sendMouseMoveEvent(50, 70);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 0x1);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        50, 70, 0x1);

                pointerEvent.resetHistory();

                sendMouseButtonEvent(50, 70, false, 0);

                expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                 50, 70, 0x0);
            });

            it('should ignore remote cursor position updates', function () {
                if (!supportsSendMouseMovementEvent()) {
                    this.skip();
                    return;
                }
                // Simple VMware Cursor Position FBU message with pointer coordinates
                // (50, 50).
                const incoming = [ 0x00, 0x00, 0x00, 0x01, 0x00, 0x32, 0x00, 0x32,
                                   0x00, 0x00, 0x00, 0x00, 0x57, 0x4d, 0x56, 0x66 ];
                client._resize(100, 100);

                const cursorSpy = sinon.spy(client, '_handleVMwareCursorPosition');
                client._sock._websocket._receiveData(new Uint8Array(incoming));
                expect(cursorSpy).to.have.been.calledOnceWith();
                cursorSpy.restore();

                expect(client._mousePos).to.deep.equal({ });
                sendMouseMoveEvent(10, 10);
                clock.tick(100);
                expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                 10, 10, 0x0);
            });

            it('should handle remote mouse position updates in pointer lock mode', function () {
                if (!supportsSendMouseMovementEvent()) {
                    this.skip();
                    return;
                }
                // Simple VMware Cursor Position FBU message with pointer coordinates
                // (50, 50).
                const incoming = [ 0x00, 0x00, 0x00, 0x01, 0x00, 0x32, 0x00, 0x32,
                                   0x00, 0x00, 0x00, 0x00, 0x57, 0x4d, 0x56, 0x66 ];
                client._resize(100, 100);

                const spy = sinon.spy();
                client.addEventListener("inputlock", spy);
                let stub = sinon.stub(document, 'pointerLockElement');
                stub.get(function () { return client._canvas; });
                client._handlePointerLockChange();
                stub.restore();
                client._sock._websocket._receiveData(new Uint8Array([0x02, 0x02]));
                expect(spy).to.have.been.calledOnce;
                expect(spy.args[0][0].detail.pointer).to.be.true;

                const cursorSpy = sinon.spy(client, '_handleVMwareCursorPosition');
                client._sock._websocket._receiveData(new Uint8Array(incoming));
                expect(cursorSpy).to.have.been.calledOnceWith();
                cursorSpy.restore();

                expect(client._mousePos).to.deep.equal({ x: 50, y: 50 });
                sendMouseMovementEvent(10, 10);
                clock.tick(100);
                expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                 60, 60, 0x0);
            });

            describe('Event Aggregation', function () {
                it('should send a single pointer event on mouse movement', function () {
                    sendMouseMoveEvent(50, 70);
                    clock.tick(100);
                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     50, 70, 0x0);
                });

                it('should delay one move if two events are too close', function () {
                    sendMouseMoveEvent(18, 30);
                    sendMouseMoveEvent(20, 50);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     18, 30, 0x0);
                    pointerEvent.resetHistory();

                    clock.tick(100);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 50, 0x0);
                });

                it('should only send first and last move of many close events', function () {
                    sendMouseMoveEvent(18, 30);
                    sendMouseMoveEvent(20, 50);
                    sendMouseMoveEvent(21, 55);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     18, 30, 0x0);
                    pointerEvent.resetHistory();

                    clock.tick(100);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     21, 55, 0x0);
                });

                // We selected the 17ms since that is ~60 FPS
                it('should send move events every 17 ms', function () {
                    sendMouseMoveEvent(1, 10);  // instant send
                    clock.tick(10);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     1, 10, 0x0);
                    pointerEvent.resetHistory();

                    sendMouseMoveEvent(2, 20);  // delayed
                    clock.tick(10);        // timeout send

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     2, 20, 0x0);
                    pointerEvent.resetHistory();

                    sendMouseMoveEvent(3, 30);  // delayed
                    clock.tick(10);
                    sendMouseMoveEvent(4, 40);  // delayed
                    clock.tick(10);        // timeout send

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     4, 40, 0x0);
                    pointerEvent.resetHistory();

                    sendMouseMoveEvent(5, 50);  // delayed

                    expect(pointerEvent).to.not.have.been.called;
                });

                it('should send waiting move events before a button press', function () {
                    sendMouseMoveEvent(13, 9);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     13, 9, 0x0);
                    pointerEvent.resetHistory();

                    sendMouseMoveEvent(20, 70);

                    expect(pointerEvent).to.not.have.been.called;

                    sendMouseButtonEvent(20, 70, true, 0);

                    expect(pointerEvent).to.have.been.calledTwice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 70, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 70, 0x1);
                });

                it('should send move events with enough time apart normally', function () {
                    sendMouseMoveEvent(58, 60);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     58, 60, 0x0);
                    pointerEvent.resetHistory();

                    clock.tick(20);

                    sendMouseMoveEvent(25, 60);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     25, 60, 0x0);
                    pointerEvent.resetHistory();
                });

                it('should not send waiting move events if disconnected', function () {
                    sendMouseMoveEvent(88, 99);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     88, 99, 0x0);
                    pointerEvent.resetHistory();

                    sendMouseMoveEvent(66, 77);
                    client.disconnect();
                    clock.tick(20);

                    expect(pointerEvent).to.not.have.been.called;
                });
            });

            it.skip('should block click events', function () {
                /* FIXME */
            });

            it.skip('should block contextmenu events', function () {
                /* FIXME */
            });
        });

        describe('Wheel Events', function () {
            function sendWheelEvent(x, y, dx, dy, mode=0) {
                let pos = elementToClient(x, y);
                let ev;

                ev = new WheelEvent('wheel',
                                    { 'screenX': pos.x + window.screenX,
                                      'screenY': pos.y + window.screenY,
                                      'clientX': pos.x,
                                      'clientY': pos.y,
                                      'deltaX': dx,
                                      'deltaY': dy,
                                      'deltaMode': mode });
                client._canvas.dispatchEvent(ev);
            }

            it('should handle wheel up event', function () {
                sendWheelEvent(10, 10, 0, -50);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 1<<3);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        10, 10, 0);
            });

            it('should handle wheel down event', function () {
                sendWheelEvent(10, 10, 0, 50);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 1<<4);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        10, 10, 0);
            });

            it('should handle wheel left event', function () {
                sendWheelEvent(10, 10, -50, 0);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 1<<5);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        10, 10, 0);
            });

            it('should handle wheel right event', function () {
                sendWheelEvent(10, 10, 50, 0);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 1<<6);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        10, 10, 0);
            });

            it('should ignore wheel when in view only', function () {
                client._viewOnly = true;

                sendWheelEvent(10, 10, 50, 0);

                expect(pointerEvent).to.not.have.been.called;
            });

            it('should accumulate wheel events if small enough', function () {
                sendWheelEvent(10, 10, 0, 20);
                sendWheelEvent(10, 10, 0, 20);

                expect(pointerEvent).to.not.have.been.called;

                sendWheelEvent(10, 10, 0, 20);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 1<<4);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        10, 10, 0);
            });

            it('should not accumulate large wheel events', function () {
                sendWheelEvent(10, 10, 0, 400);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 1<<4);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        10, 10, 0);
            });

            it('should handle line based wheel event', function () {
                sendWheelEvent(10, 10, 0, 3, 1);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 1<<4);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        10, 10, 0);
            });

            it('should handle page based wheel event', function () {
                sendWheelEvent(10, 10, 0, 3, 2);

                expect(pointerEvent).to.have.been.calledTwice;
                expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       10, 10, 1<<4);
                expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        10, 10, 0);
            });
        });

        describe('Keyboard Events', function () {
            it('should send a key message on a key press', function () {
                client._handleKeyEvent(0x41, 'KeyA', true);
                const keyMsg = {_sQ: new Uint8Array(8), _sQlen: 0, flush: () => {}};
                RFB.messages.keyEvent(keyMsg, 0x41, 1);
                expect(client._sock).to.have.sent(keyMsg._sQ);
            });

            it('should not send messages in view-only mode', function () {
                client._viewOnly = true;
                sinon.spy(client._sock, 'flush');
                client._handleKeyEvent('a', 'KeyA', true);
                expect(client._sock.flush).to.not.have.been.called;
            });
        });

        describe('Gesture event handlers', function () {
            function gestureStart(gestureType, x, y,
                                  magnitudeX = 0, magnitudeY = 0) {
                let pos = elementToClient(x, y);
                let detail = {type: gestureType, clientX: pos.x, clientY: pos.y};

                detail.magnitudeX = magnitudeX;
                detail.magnitudeY = magnitudeY;

                let ev = new CustomEvent('gesturestart', { detail: detail });
                client._canvas.dispatchEvent(ev);
            }

            function gestureMove(gestureType, x, y,
                                 magnitudeX = 0, magnitudeY = 0) {
                let pos = elementToClient(x, y);
                let detail = {type: gestureType, clientX: pos.x, clientY: pos.y};

                detail.magnitudeX = magnitudeX;
                detail.magnitudeY = magnitudeY;

                let ev = new CustomEvent('gesturemove', { detail: detail });
                client._canvas.dispatchEvent(ev);
            }

            function gestureEnd(gestureType, x, y) {
                let pos = elementToClient(x, y);
                let detail = {type: gestureType, clientX: pos.x, clientY: pos.y};
                let ev = new CustomEvent('gestureend', { detail: detail });
                client._canvas.dispatchEvent(ev);
            }

            describe('Gesture onetap', function () {
                it('should handle onetap events', function () {
                    let bmask = 0x1;

                    gestureStart('onetap', 20, 40);
                    gestureEnd('onetap', 20, 40);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                });

                it('should keep same position for multiple onetap events', function () {
                    let bmask = 0x1;

                    gestureStart('onetap', 20, 40);
                    gestureEnd('onetap', 20, 40);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureStart('onetap', 20, 50);
                    gestureEnd('onetap', 20, 50);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureStart('onetap', 30, 50);
                    gestureEnd('onetap', 30, 50);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                });

                it('should not keep same position for onetap events when too far apart', function () {
                    let bmask = 0x1;

                    gestureStart('onetap', 20, 40);
                    gestureEnd('onetap', 20, 40);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureStart('onetap', 80, 95);
                    gestureEnd('onetap', 80, 95);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           80, 95, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            80, 95, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           80, 95, 0x0);
                });

                it('should not keep same position for onetap events when enough time inbetween', function () {
                    let bmask = 0x1;

                    gestureStart('onetap', 10, 20);
                    gestureEnd('onetap', 10, 20);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           10, 20, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            10, 20, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           10, 20, 0x0);

                    pointerEvent.resetHistory();
                    this.clock.tick(1500);

                    gestureStart('onetap', 15, 20);
                    gestureEnd('onetap', 15, 20);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           15, 20, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            15, 20, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           15, 20, 0x0);

                    pointerEvent.resetHistory();
                });
            });

            describe('Gesture twotap', function () {
                it('should handle gesture twotap events', function () {
                    let bmask = 0x4;

                    gestureStart("twotap", 20, 40);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                });

                it('should keep same position for multiple twotap events', function () {
                    let bmask = 0x4;

                    for (let offset = 0;offset < 30;offset += 10) {
                        pointerEvent.resetHistory();

                        gestureStart('twotap', 20, 40 + offset);
                        gestureEnd('twotap', 20, 40 + offset);

                        expect(pointerEvent).to.have.been.calledThrice;
                        expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                               20, 40, 0x0);
                        expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                                20, 40, bmask);
                        expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                               20, 40, 0x0);
                    }
                });
            });

            describe('Gesture threetap', function () {
                it('should handle gesture start for threetap events', function () {
                    let bmask = 0x2;

                    gestureStart("threetap", 20, 40);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                });

                it('should keep same position for multiple threetap events', function () {
                    let bmask = 0x2;

                    for (let offset = 0;offset < 30;offset += 10) {
                        pointerEvent.resetHistory();

                        gestureStart('threetap', 20, 40 + offset);
                        gestureEnd('threetap', 20, 40 + offset);

                        expect(pointerEvent).to.have.been.calledThrice;
                        expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                               20, 40, 0x0);
                        expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                                20, 40, bmask);
                        expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                               20, 40, 0x0);
                    }
                });
            });

            describe('Gesture drag', function () {
                it('should handle gesture drag events', function () {
                    let bmask = 0x1;

                    gestureStart('drag', 20, 40);

                    expect(pointerEvent).to.have.been.calledTwice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);

                    pointerEvent.resetHistory();

                    gestureMove('drag', 30, 50);
                    clock.tick(50);

                    expect(pointerEvent).to.have.been.calledOnce;
                    expect(pointerEvent).to.have.been.calledWith(client._sock,
                                                                 30, 50, bmask);

                    pointerEvent.resetHistory();

                    gestureEnd('drag', 30, 50);

                    expect(pointerEvent).to.have.been.calledTwice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           30, 50, bmask);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            30, 50, 0x0);
                });
            });

            describe('Gesture long press', function () {
                it('should handle long press events', function () {
                    let bmask = 0x4;

                    gestureStart('longpress', 20, 40);

                    expect(pointerEvent).to.have.been.calledTwice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    pointerEvent.resetHistory();

                    gestureMove('longpress', 40, 60);
                    clock.tick(50);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     40, 60, bmask);

                    pointerEvent.resetHistory();

                    gestureEnd('longpress', 40, 60);

                    expect(pointerEvent).to.have.been.calledTwice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           40, 60, bmask);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            40, 60, 0x0);
                });
            });

            describe('Gesture twodrag', function () {
                it('should handle gesture twodrag up events', function () {
                    let bmask = 0x10; // Button mask for scroll down

                    gestureStart('twodrag', 20, 40, 0, 0);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureMove('twodrag', 20, 40, 0, -60);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                });

                it('should handle gesture twodrag down events', function () {
                    let bmask = 0x8; // Button mask for scroll up

                    gestureStart('twodrag', 20, 40, 0, 0);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureMove('twodrag', 20, 40, 0, 60);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                });

                it('should handle gesture twodrag right events', function () {
                    let bmask = 0x20; // Button mask for scroll right

                    gestureStart('twodrag', 20, 40, 0, 0);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureMove('twodrag', 20, 40, 60, 0);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                });

                it('should handle gesture twodrag left events', function () {
                    let bmask = 0x40; // Button mask for scroll left

                    gestureStart('twodrag', 20, 40, 0, 0);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureMove('twodrag', 20, 40, -60, 0);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                });

                it('should handle gesture twodrag diag events', function () {
                    let scrlUp = 0x8; // Button mask for scroll up
                    let scrlRight = 0x20; // Button mask for scroll right

                    gestureStart('twodrag', 20, 40, 0, 0);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureMove('twodrag', 20, 40, 60, 60);

                    expect(pointerEvent).to.have.been.callCount(5);
                    expect(pointerEvent.getCall(0)).to.have.been.calledWith(client._sock,
                                                                            20, 40, 0x0);
                    expect(pointerEvent.getCall(1)).to.have.been.calledWith(client._sock,
                                                                            20, 40, scrlUp);
                    expect(pointerEvent.getCall(2)).to.have.been.calledWith(client._sock,
                                                                            20, 40, 0x0);
                    expect(pointerEvent.getCall(3)).to.have.been.calledWith(client._sock,
                                                                            20, 40, scrlRight);
                    expect(pointerEvent.getCall(4)).to.have.been.calledWith(client._sock,
                                                                            20, 40, 0x0);
                });

                it('should handle multiple small gesture twodrag events', function () {
                    let bmask = 0x8; // Button mask for scroll up

                    gestureStart('twodrag', 20, 40, 0, 0);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureMove('twodrag', 20, 40, 0, 10);
                    clock.tick(50);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureMove('twodrag', 20, 40, 0, 20);
                    clock.tick(50);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureMove('twodrag', 20, 40, 0, 60);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                });

                it('should handle large gesture twodrag events', function () {
                    let bmask = 0x8; // Button mask for scroll up

                    gestureStart('twodrag', 30, 50, 0, 0);

                    expect(pointerEvent).
                        to.have.been.calledOnceWith(client._sock, 30, 50, 0x0);

                    pointerEvent.resetHistory();

                    gestureMove('twodrag', 30, 50, 0, 200);

                    expect(pointerEvent).to.have.callCount(7);
                    expect(pointerEvent.getCall(0)).to.have.been.calledWith(client._sock,
                                                                            30, 50, 0x0);
                    expect(pointerEvent.getCall(1)).to.have.been.calledWith(client._sock,
                                                                            30, 50, bmask);
                    expect(pointerEvent.getCall(2)).to.have.been.calledWith(client._sock,
                                                                            30, 50, 0x0);
                    expect(pointerEvent.getCall(3)).to.have.been.calledWith(client._sock,
                                                                            30, 50, bmask);
                    expect(pointerEvent.getCall(4)).to.have.been.calledWith(client._sock,
                                                                            30, 50, 0x0);
                    expect(pointerEvent.getCall(5)).to.have.been.calledWith(client._sock,
                                                                            30, 50, bmask);
                    expect(pointerEvent.getCall(6)).to.have.been.calledWith(client._sock,
                                                                            30, 50, 0x0);
                });
            });

            describe('Gesture pinch', function () {
                it('should handle gesture pinch in events', function () {
                    let keysym = KeyTable.XK_Control_L;
                    let bmask = 0x10; // Button mask for scroll down

                    gestureStart('pinch', 20, 40, 90, 90);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);
                    expect(keyEvent).to.not.have.been.called;

                    pointerEvent.resetHistory();

                    gestureMove('pinch', 20, 40, 30, 30);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);

                    expect(keyEvent).to.have.been.calledTwice;
                    expect(keyEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       keysym, 1);
                    expect(keyEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        keysym, 0);

                    expect(keyEvent.firstCall).to.have.been.calledBefore(pointerEvent.secondCall);
                    expect(keyEvent.lastCall).to.have.been.calledAfter(pointerEvent.lastCall);

                    pointerEvent.resetHistory();
                    keyEvent.resetHistory();

                    gestureEnd('pinch', 20, 40);

                    expect(pointerEvent).to.not.have.been.called;
                    expect(keyEvent).to.not.have.been.called;
                });

                it('should handle gesture pinch out events', function () {
                    let keysym = KeyTable.XK_Control_L;
                    let bmask = 0x8; // Button mask for scroll up

                    gestureStart('pinch', 10, 20, 10, 20);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     10, 20, 0x0);
                    expect(keyEvent).to.not.have.been.called;

                    pointerEvent.resetHistory();

                    gestureMove('pinch', 10, 20, 70, 80);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           10, 20, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            10, 20, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           10, 20, 0x0);

                    expect(keyEvent).to.have.been.calledTwice;
                    expect(keyEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       keysym, 1);
                    expect(keyEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        keysym, 0);

                    expect(keyEvent.firstCall).to.have.been.calledBefore(pointerEvent.secondCall);
                    expect(keyEvent.lastCall).to.have.been.calledAfter(pointerEvent.lastCall);

                    pointerEvent.resetHistory();
                    keyEvent.resetHistory();

                    gestureEnd('pinch', 10, 20);

                    expect(pointerEvent).to.not.have.been.called;
                    expect(keyEvent).to.not.have.been.called;
                });

                it('should handle large gesture pinch', function () {
                    let keysym = KeyTable.XK_Control_L;
                    let bmask = 0x10; // Button mask for scroll down

                    gestureStart('pinch', 20, 40, 150, 150);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);
                    expect(keyEvent).to.not.have.been.called;

                    pointerEvent.resetHistory();

                    gestureMove('pinch', 20, 40, 30, 30);

                    expect(pointerEvent).to.have.been.callCount(5);
                    expect(pointerEvent.getCall(0)).to.have.been.calledWith(client._sock,
                                                                            20, 40, 0x0);
                    expect(pointerEvent.getCall(1)).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.getCall(2)).to.have.been.calledWith(client._sock,
                                                                            20, 40, 0x0);
                    expect(pointerEvent.getCall(3)).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.getCall(4)).to.have.been.calledWith(client._sock,
                                                                            20, 40, 0x0);

                    expect(keyEvent).to.have.been.calledTwice;
                    expect(keyEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       keysym, 1);
                    expect(keyEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        keysym, 0);

                    expect(keyEvent.firstCall).to.have.been.calledBefore(pointerEvent.secondCall);
                    expect(keyEvent.lastCall).to.have.been.calledAfter(pointerEvent.lastCall);

                    pointerEvent.resetHistory();
                    keyEvent.resetHistory();

                    gestureEnd('pinch', 20, 40);

                    expect(pointerEvent).to.not.have.been.called;
                    expect(keyEvent).to.not.have.been.called;
                });

                it('should handle multiple small gesture pinch out events', function () {
                    let keysym = KeyTable.XK_Control_L;
                    let bmask = 0x8; // Button mask for scroll down

                    gestureStart('pinch', 20, 40, 0, 10);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);
                    expect(keyEvent).to.not.have.been.called;

                    pointerEvent.resetHistory();

                    gestureMove('pinch', 20, 40, 0, 30);
                    clock.tick(50);

                    expect(pointerEvent).to.have.been.calledWith(client._sock,
                                                                 20, 40, 0x0);

                    pointerEvent.resetHistory();

                    gestureMove('pinch', 20, 40, 0, 60);
                    clock.tick(50);

                    expect(pointerEvent).to.have.been.calledWith(client._sock,
                                                                 20, 40, 0x0);

                    pointerEvent.resetHistory();
                    keyEvent.resetHistory();

                    gestureMove('pinch', 20, 40, 0, 90);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);

                    expect(keyEvent).to.have.been.calledTwice;
                    expect(keyEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                       keysym, 1);
                    expect(keyEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                        keysym, 0);

                    expect(keyEvent.firstCall).to.have.been.calledBefore(pointerEvent.secondCall);
                    expect(keyEvent.lastCall).to.have.been.calledAfter(pointerEvent.lastCall);

                    pointerEvent.resetHistory();
                    keyEvent.resetHistory();

                    gestureEnd('pinch', 20, 40);

                    expect(keyEvent).to.not.have.been.called;
                });

                it('should send correct key control code', function () {
                    let keysym = KeyTable.XK_Control_L;
                    let code = 0x1d;
                    let bmask = 0x10; // Button mask for scroll down

                    client._qemuExtKeyEventSupported = true;

                    gestureStart('pinch', 20, 40, 90, 90);

                    expect(pointerEvent).to.have.been.calledOnceWith(client._sock,
                                                                     20, 40, 0x0);
                    expect(qemuKeyEvent).to.not.have.been.called;

                    pointerEvent.resetHistory();

                    gestureMove('pinch', 20, 40, 30, 30);

                    expect(pointerEvent).to.have.been.calledThrice;
                    expect(pointerEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);
                    expect(pointerEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            20, 40, bmask);
                    expect(pointerEvent.thirdCall).to.have.been.calledWith(client._sock,
                                                                           20, 40, 0x0);

                    expect(qemuKeyEvent).to.have.been.calledTwice;
                    expect(qemuKeyEvent.firstCall).to.have.been.calledWith(client._sock,
                                                                           keysym,
                                                                           true,
                                                                           code);
                    expect(qemuKeyEvent.secondCall).to.have.been.calledWith(client._sock,
                                                                            keysym,
                                                                            false,
                                                                            code);

                    expect(qemuKeyEvent.firstCall).to.have.been.calledBefore(pointerEvent.secondCall);
                    expect(qemuKeyEvent.lastCall).to.have.been.calledAfter(pointerEvent.lastCall);

                    pointerEvent.resetHistory();
                    qemuKeyEvent.resetHistory();

                    gestureEnd('pinch', 20, 40);

                    expect(pointerEvent).to.not.have.been.called;
                    expect(qemuKeyEvent).to.not.have.been.called;
                });
            });
        });

        describe('WebSocket Events', function () {
            // message events
            it('should do nothing if we receive an empty message and have nothing in the queue', function () {
                client._normalMsg = sinon.spy();
                client._sock._websocket._receiveData(new Uint8Array([]));
                expect(client._normalMsg).to.not.have.been.called;
            });

            it('should handle a message in the connected state as a normal message', function () {
                client._normalMsg = sinon.spy();
                client._sock._websocket._receiveData(new Uint8Array([1, 2, 3]));
                expect(client._normalMsg).to.have.been.called;
            });

            it('should handle a message in any non-disconnected/failed state like an init message', function () {
                client._rfbConnectionState = 'connecting';
                client._rfbInitState = 'ProtocolVersion';
                client._initMsg = sinon.spy();
                client._sock._websocket._receiveData(new Uint8Array([1, 2, 3]));
                expect(client._initMsg).to.have.been.called;
            });

            it('should process all normal messages directly', function () {
                const spy = sinon.spy();
                client.addEventListener("bell", spy);
                client._sock._websocket._receiveData(new Uint8Array([0x02, 0x02]));
                expect(spy).to.have.been.calledTwice;
            });

            // open events
            it('should update the state to ProtocolVersion on open (if the state is "connecting")', function () {
                client = new RFB(document.createElement('div'), 'wss://host:8675');
                this.clock.tick();
                client._sock._websocket._open();
                expect(client._rfbInitState).to.equal('ProtocolVersion');
            });

            it('should fail if we are not currently ready to connect and we get an "open" event', function () {
                sinon.spy(client, "_fail");
                client._rfbConnectionState = 'connected';
                client._sock._websocket._open();
                expect(client._fail).to.have.been.calledOnce;
            });

            // close events
            it('should transition to "disconnected" from "disconnecting" on a close event', function () {
                const real = client._sock._websocket.close;
                client._sock._websocket.close = () => {};
                client.disconnect();
                expect(client._rfbConnectionState).to.equal('disconnecting');
                client._sock._websocket.close = real;
                client._sock._websocket.close();
                expect(client._rfbConnectionState).to.equal('disconnected');
            });

            it('should fail if we get a close event while connecting', function () {
                sinon.spy(client, "_fail");
                client._rfbConnectionState = 'connecting';
                client._sock._websocket.close();
                expect(client._fail).to.have.been.calledOnce;
            });

            it('should unregister close event handler', function () {
                sinon.spy(client._sock, 'off');
                client.disconnect();
                client._sock._websocket.close();
                expect(client._sock.off).to.have.been.calledWith('close');
            });

            // error events do nothing
        });
    });

    describe('Quality level setting', function () {
        const defaultQuality = 6;

        let client;

        beforeEach(function () {
            client = makeRFB();
            sinon.spy(RFB.messages, "clientEncodings");
        });

        afterEach(function () {
            RFB.messages.clientEncodings.restore();
        });

        it(`should equal ${defaultQuality} by default`, function () {
            expect(client._qualityLevel).to.equal(defaultQuality);
        });

        it('should ignore non-integers when set', function () {
            client.qualityLevel = '1';
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client.qualityLevel = 1.5;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client.qualityLevel = null;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client.qualityLevel = undefined;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client.qualityLevel = {};
            expect(RFB.messages.clientEncodings).to.not.have.been.called;
        });

        it('should ignore integers out of range [0, 9]', function () {
            client.qualityLevel = -1;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client.qualityLevel = 10;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;
        });

        it('should send clientEncodings with new quality value', function () {
            let newQuality;

            newQuality = 8;
            client.qualityLevel = newQuality;
            expect(client.qualityLevel).to.equal(newQuality);
            expect(RFB.messages.clientEncodings).to.have.been.calledOnce;
            expect(RFB.messages.clientEncodings.getCall(0).args[1]).to.include(encodings.pseudoEncodingQualityLevel0 + newQuality);
        });

        it('should not send clientEncodings if quality is the same', function () {
            let newQuality;

            newQuality = 2;
            client.qualityLevel = newQuality;
            expect(RFB.messages.clientEncodings).to.have.been.calledOnce;
            expect(RFB.messages.clientEncodings.getCall(0).args[1]).to.include(encodings.pseudoEncodingQualityLevel0 + newQuality);

            RFB.messages.clientEncodings.resetHistory();

            client.qualityLevel = newQuality;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;
        });

        it('should not send clientEncodings if not in connected state', function () {
            let newQuality;

            client._rfbConnectionState = '';
            newQuality = 2;
            client.qualityLevel = newQuality;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client._rfbConnectionState = 'connnecting';
            newQuality = 6;
            client.qualityLevel = newQuality;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client._rfbConnectionState = 'connected';
            newQuality = 5;
            client.qualityLevel = newQuality;
            expect(RFB.messages.clientEncodings).to.have.been.calledOnce;
            expect(RFB.messages.clientEncodings.getCall(0).args[1]).to.include(encodings.pseudoEncodingQualityLevel0 + newQuality);
        });
    });

    describe('Compression level setting', function () {
        const defaultCompression = 2;

        let client;

        beforeEach(function () {
            client = makeRFB();
            sinon.spy(RFB.messages, "clientEncodings");
        });

        afterEach(function () {
            RFB.messages.clientEncodings.restore();
        });

        it(`should equal ${defaultCompression} by default`, function () {
            expect(client._compressionLevel).to.equal(defaultCompression);
        });

        it('should ignore non-integers when set', function () {
            client.compressionLevel = '1';
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client.compressionLevel = 1.5;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client.compressionLevel = null;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client.compressionLevel = undefined;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client.compressionLevel = {};
            expect(RFB.messages.clientEncodings).to.not.have.been.called;
        });

        it('should ignore integers out of range [0, 9]', function () {
            client.compressionLevel = -1;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client.compressionLevel = 10;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;
        });

        it('should send clientEncodings with new compression value', function () {
            let newCompression;

            newCompression = 5;
            client.compressionLevel = newCompression;
            expect(client.compressionLevel).to.equal(newCompression);
            expect(RFB.messages.clientEncodings).to.have.been.calledOnce;
            expect(RFB.messages.clientEncodings.getCall(0).args[1]).to.include(encodings.pseudoEncodingCompressLevel0 + newCompression);
        });

        it('should not send clientEncodings if compression is the same', function () {
            let newCompression;

            newCompression = 9;
            client.compressionLevel = newCompression;
            expect(RFB.messages.clientEncodings).to.have.been.calledOnce;
            expect(RFB.messages.clientEncodings.getCall(0).args[1]).to.include(encodings.pseudoEncodingCompressLevel0 + newCompression);

            RFB.messages.clientEncodings.resetHistory();

            client.compressionLevel = newCompression;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;
        });

        it('should not send clientEncodings if not in connected state', function () {
            let newCompression;

            client._rfbConnectionState = '';
            newCompression = 7;
            client.compressionLevel = newCompression;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client._rfbConnectionState = 'connnecting';
            newCompression = 6;
            client.compressionLevel = newCompression;
            expect(RFB.messages.clientEncodings).to.not.have.been.called;

            RFB.messages.clientEncodings.resetHistory();

            client._rfbConnectionState = 'connected';
            newCompression = 5;
            client.compressionLevel = newCompression;
            expect(RFB.messages.clientEncodings).to.have.been.calledOnce;
            expect(RFB.messages.clientEncodings.getCall(0).args[1]).to.include(encodings.pseudoEncodingCompressLevel0 + newCompression);
        });
    });
});

describe('RFB messages', function () {
    let sock;

    before(function () {
        FakeWebSocket.replace();
        sock = new Websock();
        sock.open();
    });

    after(function () {
        FakeWebSocket.restore();
    });

    describe('Extended Clipboard Handling Send', function () {
        beforeEach(function () {
            sinon.spy(RFB.messages, 'clientCutText');
        });

        afterEach(function () {
            RFB.messages.clientCutText.restore();
        });

        it('should call clientCutText with correct Caps data', function () {
            let formats = {
                0: 2,
                2: 4121
            };
            let expectedData = new Uint8Array([0x1F, 0x00, 0x00, 0x05,
                                               0x00, 0x00, 0x00, 0x02,
                                               0x00, 0x00, 0x10, 0x19]);
            let actions = [
                1 << 24,  // Caps
                1 << 25,  // Request
                1 << 26,  // Peek
                1 << 27,  // Notify
                1 << 28   // Provide
            ];

            RFB.messages.extendedClipboardCaps(sock, actions, formats);
            expect(RFB.messages.clientCutText).to.have.been.calledOnce;
            expect(RFB.messages.clientCutText).to.have.been.calledWith(sock, expectedData);
        });

        it('should call clientCutText with correct Request data', function () {
            let formats = new Uint8Array([0x01]);
            let expectedData = new Uint8Array([0x02, 0x00, 0x00, 0x01]);

            RFB.messages.extendedClipboardRequest(sock, formats);
            expect(RFB.messages.clientCutText).to.have.been.calledOnce;
            expect(RFB.messages.clientCutText).to.have.been.calledWith(sock, expectedData);
        });

        it('should call clientCutText with correct Notify data', function () {
            let formats = new Uint8Array([0x01]);
            let expectedData = new Uint8Array([0x08, 0x00, 0x00, 0x01]);

            RFB.messages.extendedClipboardNotify(sock, formats);
            expect(RFB.messages.clientCutText).to.have.been.calledOnce;
            expect(RFB.messages.clientCutText).to.have.been.calledWith(sock, expectedData);
        });

        it('should call clientCutText with correct Provide data', function () {
            let testText = "Test string";
            let expectedText = encodeUTF8(testText + "\0");

            let deflatedData =  deflateWithSize(expectedText);

            // Build Expected with flags and deflated data
            let expectedData = new Uint8Array(4 + deflatedData.length);
            expectedData[0] = 0x10; // The client capabilities
            expectedData[1] = 0x00; // Reserved flags
            expectedData[2] = 0x00; // Reserved flags
            expectedData[3] = 0x01; // The formats client supports
            expectedData.set(deflatedData, 4);

            RFB.messages.extendedClipboardProvide(sock, [0x01], [testText]);
            expect(RFB.messages.clientCutText).to.have.been.calledOnce;
            expect(RFB.messages.clientCutText).to.have.been.calledWith(sock, expectedData, true);

        });

        describe('End of line characters', function () {
            it('Carriage return', function () {

                let testText = "Hello\rworld\r\r!";
                let expectedText = encodeUTF8("Hello\r\nworld\r\n\r\n!\0");

                let deflatedData =  deflateWithSize(expectedText);

                // Build Expected with flags and deflated data
                let expectedData = new Uint8Array(4 + deflatedData.length);
                expectedData[0] = 0x10; // The client capabilities
                expectedData[1] = 0x00; // Reserved flags
                expectedData[2] = 0x00; // Reserved flags
                expectedData[3] = 0x01; // The formats client supports
                expectedData.set(deflatedData, 4);

                RFB.messages.extendedClipboardProvide(sock, [0x01], [testText]);
                expect(RFB.messages.clientCutText).to.have.been.calledOnce;
                expect(RFB.messages.clientCutText).to.have.been.calledWith(sock, expectedData, true);
            });

            it('Carriage return Line feed', function () {

                let testText = "Hello\r\n\r\nworld\r\n!";
                let expectedText = encodeUTF8(testText + "\0");

                let deflatedData =  deflateWithSize(expectedText);

                // Build Expected with flags and deflated data
                let expectedData = new Uint8Array(4 + deflatedData.length);
                expectedData[0] = 0x10; // The client capabilities
                expectedData[1] = 0x00; // Reserved flags
                expectedData[2] = 0x00; // Reserved flags
                expectedData[3] = 0x01; // The formats client supports
                expectedData.set(deflatedData, 4);

                RFB.messages.extendedClipboardProvide(sock, [0x01], [testText]);
                expect(RFB.messages.clientCutText).to.have.been.calledOnce;
                expect(RFB.messages.clientCutText).to.have.been.calledWith(sock, expectedData, true);
            });

            it('Line feed', function () {
                let testText = "Hello\n\n\nworld\n!";
                let expectedText = encodeUTF8("Hello\r\n\r\n\r\nworld\r\n!\0");

                let deflatedData =  deflateWithSize(expectedText);

                // Build Expected with flags and deflated data
                let expectedData = new Uint8Array(4 + deflatedData.length);
                expectedData[0] = 0x10; // The client capabilities
                expectedData[1] = 0x00; // Reserved flags
                expectedData[2] = 0x00; // Reserved flags
                expectedData[3] = 0x01; // The formats client supports
                expectedData.set(deflatedData, 4);

                RFB.messages.extendedClipboardProvide(sock, [0x01], [testText]);
                expect(RFB.messages.clientCutText).to.have.been.calledOnce;
                expect(RFB.messages.clientCutText).to.have.been.calledWith(sock, expectedData, true);
            });

            it('Carriage return and Line feed mixed', function () {
                let testText = "\rHello\r\n\rworld\n\n!";
                let expectedText = encodeUTF8("\r\nHello\r\n\r\nworld\r\n\r\n!\0");

                let deflatedData =  deflateWithSize(expectedText);

                // Build Expected with flags and deflated data
                let expectedData = new Uint8Array(4 + deflatedData.length);
                expectedData[0] = 0x10; // The client capabilities
                expectedData[1] = 0x00; // Reserved flags
                expectedData[2] = 0x00; // Reserved flags
                expectedData[3] = 0x01; // The formats client supports
                expectedData.set(deflatedData, 4);

                RFB.messages.extendedClipboardProvide(sock, [0x01], [testText]);
                expect(RFB.messages.clientCutText).to.have.been.calledOnce;
                expect(RFB.messages.clientCutText).to.have.been.calledWith(sock, expectedData, true);
            });
        });
    });
});
