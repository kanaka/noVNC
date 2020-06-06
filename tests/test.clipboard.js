const expect = chai.expect;

import Clipboard from '../core/clipboard.js';

describe('Automatic Clipboard Sync', function () {
    "use strict";

    if (Clipboard.isSupported) {
        beforeEach(function () {
            if (navigator.clipboard.writeText) {
                sinon.spy(navigator.clipboard, 'writeText');
            }
            if (navigator.clipboard.readText) {
                sinon.spy(navigator.clipboard, 'readText');
            }
        });

        afterEach(function () {
            if (navigator.clipboard.writeText) {
                navigator.clipboard.writeText.restore();
            }
            if (navigator.clipboard.readText) {
                navigator.clipboard.readText.restore();
            }
        });
    }

    it('incoming clipboard data from the server is copied to the local clipboard', function () {
        const text = 'Random string for testing';
        const clipboard = new Clipboard();
        if (Clipboard.isSupported) {
            const clipboardData = new DataTransfer();
            clipboardData.setData("text/plain", text);
            const clipboardEvent = new ClipboardEvent('paste', { clipboardData });
            // Force initialization since the constructor is broken in Firefox
            if (!clipboardEvent.clipboardData.items.length) {
                clipboardEvent.clipboardData.items.add(text, "text/plain");
            }
            clipboard._handleCopy(clipboardEvent);
            if (navigator.clipboard.writeText) {
                expect(navigator.clipboard.writeText).to.have.been.calledWith(text);
            }
        }
    });

    it('should copy local pasted data to the server clipboard', function () {
        const text = 'Another random string for testing';
        const clipboard = new Clipboard();
        clipboard.onpaste = pasterText => expect(pasterText).to.equal(text);
        if (Clipboard.isSupported) {
            const clipboardData = new DataTransfer();
            clipboardData.setData("text/plain", text);
            const clipboardEvent = new ClipboardEvent('paste', { clipboardData });
            // Force initialization since the constructor is broken in Firefox
            if (!clipboardEvent.clipboardData.items.length) {
                clipboardEvent.clipboardData.items.add(text, "text/plain");
            }
            clipboard._handlePaste(clipboardEvent);
            if (navigator.clipboard.readText) {
                expect(navigator.clipboard.readText).to.have.been.called;
            }
        }
    });
});
