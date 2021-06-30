# noVNC API

The interface of the noVNC client consists of a single RFB object that
is instantiated once per connection.

## RFB

The `RFB` object represents a single connection to a VNC server. It
communicates using a WebSocket that must provide a standard RFB
protocol stream.

### Constructor

[`RFB()`](#rfb-1)
  - Creates and returns a new `RFB` object.

### Properties

`viewOnly`
  - Is a `boolean` indicating if any events (e.g. key presses or mouse
    movement) should be prevented from being sent to the server.
    Disabled by default.

`focusOnClick`
  - Is a `boolean` indicating if keyboard focus should automatically be
    moved to the remote session when a `mousedown` or `touchstart`
    event is received. Enabled by default.

`clipViewport`
  - Is a `boolean` indicating if the remote session should be clipped
    to its container. When disabled scrollbars will be shown to handle
    the resulting overflow. Disabled by default.

`dragViewport`
  - Is a `boolean` indicating if mouse events should control the
    relative position of a clipped remote session. Only relevant if
    `clipViewport` is enabled. Disabled by default.

`scaleViewport`
  - Is a `boolean` indicating if the remote session should be scaled
    locally so it fits its container. When disabled it will be centered
    if the remote session is smaller than its container, or handled
    according to `clipViewport` if it is larger. Disabled by default.

`resizeSession`
  - Is a `boolean` indicating if a request to resize the remote session
    should be sent whenever the container changes dimensions. Disabled
    by default.

`showDotCursor`
  - Is a `boolean` indicating whether a dot cursor should be shown
    instead of a zero-sized or fully-transparent cursor if the server
    sets such invisible cursor. Disabled by default.

`background`
  - Is a valid CSS [background](https://developer.mozilla.org/en-US/docs/Web/CSS/background)
    style value indicating which background style should be applied
    to the element containing the remote session screen. The default value is `rgb(40, 40, 40)`
    (solid gray color).

`qualityLevel`
  - Is an `int` in range `[0-9]` controlling the desired JPEG quality.
    Value `0` implies low quality and `9` implies high quality.
    Default value is `6`.

`compressionLevel`
  - Is an `int` in range `[0-9]` controlling the desired compression
    level. Value `0` means no compression. Level 1 uses a minimum of CPU
    resources and achieves weak compression ratios, while level 9 offers
    best compression but is slow in terms of CPU consumption on the server
    side. Use high levels with very slow network connections.
    Default value is `2`.

`capabilities` *Read only*
  - Is an `Object` indicating which optional extensions are available
    on the server. Some methods may only be called if the corresponding
    capability is set. The following capabilities are defined:

    | name     | type      | description
    | -------- | --------- | -----------
    | `power`  | `boolean` | Machine power control is available

### Events

[`connect`](#connect)
  - The `connect` event is fired when the `RFB` object has completed
    the connection and handshaking with the server.

[`disconnect`](#disconnected)
  - The `disconnect` event is fired when the `RFB` object disconnects.

[`credentialsrequired`](#credentialsrequired)
  - The `credentialsrequired` event is fired when more credentials must
    be given to continue.

[`securityfailure`](#securityfailure)
  - The `securityfailure` event is fired when the security negotiation
    with the server fails.

[`clipboard`](#clipboard)
  - The `clipboard` event is fired when clipboard data is received from
    the server.

[`bell`](#bell)
  - The `bell` event is fired when a audible bell request is received
    from the server.

[`desktopname`](#desktopname)
  - The `desktopname` event is fired when the remote desktop name
    changes.

[`capabilities`](#capabilities)
  - The `capabilities` event is fired when `RFB.capabilities` is
    updated.

[`inputlock`](#inputlock)
  - The `inputlock` event is fired when an input lock is acquired (or released)
    by the canvas.

### Methods

[`RFB.disconnect()`](#rfbdisconnect)
  - Disconnect from the server.

[`RFB.sendCredentials()`](#rfbsendcredentials)
  - Send credentials to server. Should be called after the
    [`credentialsrequired`](#credentialsrequired) event has fired.

[`RFB.sendKey()`](#rfbsendKey)
  - Send a key event.

[`RFB.sendCtrlAltDel()`](#rfbsendctrlaltdel)
  - Send Ctrl-Alt-Del key sequence.

[`RFB.focus()`](#rfbfocus)
  - Move keyboard focus to the remote session.

[`RFB.blur()`](#rfbblur)
  - Remove keyboard focus from the remote session.

[`RFB.machineShutdown()`](#rfbmachineshutdown)
  - Request a shutdown of the remote machine.

[`RFB.machineReboot()`](#rfbmachinereboot)
  - Request a reboot of the remote machine.

[`RFB.machineReset()`](#rfbmachinereset)
  - Request a reset of the remote machine.

[`RFB.clipboardPasteFrom()`](#rfbclipboardPasteFrom)
  - Send clipboard contents to server.

[`RFB.requestInputLock()`](#rfbrequestInputLock)
  - Requests that the RFB canvas acquire an input lock.

### Details

#### RFB()

The `RFB()` constructor returns a new `RFB` object and initiates a new
connection to a specified VNC server.

##### Syntax

    let rfb = new RFB( target, url [, options] );

###### Parameters

**`target`**
  - A block [`HTMLElement`](https://developer.mozilla.org/en-US/docs/Web/API/HTMLElement)
    that specifies where the `RFB` object should attach itself. The
    existing contents of the `HTMLElement` will be untouched, but new
    elements will be added during the lifetime of the `RFB` object.

**`urlOrDataChannel`**
  - A `DOMString` specifying the VNC server to connect to. This must be
    a valid WebSocket URL. This can also be a `WebSocket` or `RTCDataChannel`.

**`options`** *Optional*
  - An `Object` specifying extra details about how the connection
    should be made.

    Possible options:

    `shared`
      - A `boolean` indicating if the remote server should be shared or
        if any other connected clients should be disconnected. Enabled
        by default.

    `credentials`
      - An `Object` specifying the credentials to provide to the server
        when authenticating. The following credentials are possible:

        | name         | type        | description
        | ------------ | ----------- | -----------
        | `"username"` | `DOMString` | The user that authenticates
        | `"password"` | `DOMString` | Password for the user
        | `"target"`   | `DOMString` | Target machine or session

    `repeaterID`
      - A `DOMString` specifying the ID to provide to any VNC repeater
        encountered.

    `wsProtocols`
      - An `Array` of `DOMString`s specifying the sub-protocols to use
        in the WebSocket connection. Empty by default.

#### connect

The `connect` event is fired after all the handshaking with the server
is completed and the connection is fully established. After this event
the `RFB` object is ready to recieve graphics updates and to send input.

#### disconnect

The `disconnect` event is fired when the connection has been
terminated. The `detail` property is an `Object` that contains the
property `clean`. `clean` is a `boolean` indicating if the termination
was clean or not. In the event of an unexpected termination or an error
`clean` will be set to false.

#### credentialsrequired

The `credentialsrequired` event is fired when the server requests more
credentials than were specified to [`RFB()`](#rfb-1). The `detail`
property is an `Object` containing the property `types` which is an
`Array` of `DOMString` listing the credentials that are required.

#### securityfailure

The `securityfailure` event is fired when the handshaking process with
the server fails during the security negotiation step. The `detail`
property is an `Object` containing the following properties:

| Property | Type        | Description
| -------- | ----------- | -----------
| `status` | `long`      | The failure status code
| `reason` | `DOMString` | The **optional** reason for the failure

The property `status` corresponds to the
[SecurityResult](https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#securityresult)
status code in cases of failure. A status of zero will not be sent in
this event since that indicates a successful security handshaking
process. The optional property `reason` is provided by the server and
thus the language of the string is not known. However most servers will
probably send English strings. The server can choose to not send a
reason and in these cases the `reason` property will be omitted.

#### clipboard

The `clipboard` event is fired when the server has sent clipboard data.
The `detail` property is an `Object` containing the property `text`
which is a `DOMString` with the clipboard data.

#### bell

The `bell` event is fired when the server has requested an audible
bell.

#### desktopname

The `desktopname` event is fired when the name of the remote desktop
changes. The `detail` property is an `Object` with the property `name`
which is a `DOMString` specifying the new name.

#### capabilities

The `capabilities` event is fired whenever an entry is added or removed
from `RFB.capabilities`. The `detail` property is an `Object` with the
property `capabilities` containing the new value of `RFB.capabilities`.

#### inputlock

The `inputlock` event is fired after a request to acquire an input lock or
whenever the state of the canvas' input lock has changed, the latter typically
occurs because the lock was released by the user pressing the ESC key or
performing a browser-specific gesture.  The `detail` property is an `Object`
with the property `pointer` containing whether the Pointer Lock is currently
held or not.

#### RFB.disconnect()

The `RFB.disconnect()` method is used to disconnect from the currently
connected server.

##### Syntax

    RFB.disconnect( );

#### RFB.sendCredentials()

The `RFB.sendCredentials()` method is used to provide the missing
credentials after a `credentialsrequired` event has been fired.

##### Syntax

    RFB.sendCredentials( credentials );

###### Parameters

**`credentials`**
  - An `Object` specifying the credentials to provide to the server
    when authenticating. See [`RFB()`](#rfb-1) for details.

#### RFB.sendKey()

The `RFB.sendKey()` method is used to send a key event to the server.

##### Syntax

    RFB.sendKey( keysym, code [, down] );

###### Parameters

**`keysym`**
  - A `long` specifying the RFB keysym to send. Can be `0` if a valid
    **`code`** is specified.

**`code`**
  - A `DOMString` specifying the physical key to send. Valid values are
    those that can be specified to
    [`KeyboardEvent.code`](https://developer.mozilla.org/en-US/docs/Web/API/KeyboardEvent/code).
    If the physical key cannot be determined then `null` shall be
    specified.

**`down`** *Optional*
  - A `boolean` specifying if a press or a release event should be
    sent. If omitted then both a press and release event are sent.

#### RFB.sendCtrlAltDel()

The `RFB.sendCtrlAltDel()` method is used to send the key sequence
*left Control*, *left Alt*, *Delete*. This is a convenience wrapper
around [`RFB.sendKey()`](#rfbsendkey).

##### Syntax

    RFB.sendCtrlAltDel( );

#### RFB.focus()

The `RFB.focus()` method sets the keyboard focus on the remote session.
Keyboard events will be sent to the remote server after this point.

##### Syntax

    RFB.focus( );

#### RFB.blur()

The `RFB.blur()` method remove keyboard focus on the remote session.
Keyboard events will no longer be sent to the remote server after this
point.

##### Syntax

    RFB.blur( );

#### RFB.machineShutdown()

The `RFB.machineShutdown()` method is used to request to shut down the
remote machine. The capability `power` must be set for this method to
have any effect.

##### Syntax

    RFB.machineShutdown( );

#### RFB.machineReboot()

The `RFB.machineReboot()` method is used to request a clean reboot of
the remote machine. The capability `power` must be set for this method
to have any effect.

##### Syntax

    RFB.machineReboot( );

#### RFB.machineReset()

The `RFB.machineReset()` method is used to request a forced reset of
the remote machine. The capability `power` must be set for this method
to have any effect.

##### Syntax

    RFB.machineReset( );

#### RFB.clipboardPasteFrom()

The `RFB.clipboardPasteFrom()` method is used to send clipboard data
to the remote server.

##### Syntax

    RFB.clipboardPasteFrom( text );

###### Parameters

**`text`**
  - A `DOMString` specifying the clipboard data to send.

#### RFB.requestInputLock()

The `RFB.requestInputLock()` method is used to request that the RFB canvas hold
an input lock. An `inputlock` event will be fired with the result of the
acquisition of the requested locks.

##### Syntax

    RFB.requestInputLock( { pointer: true } );

###### Parameters

**`pointer`**
  - Requests to acquire a [Pointer
    Lock](https://developer.mozilla.org/en-US/docs/Web/API/Pointer_Lock_API),
    which hides the local mouse cursor and provides relative motion events.
    This must be called directly from an event handler where a user has
    directly interacted with an element through an [engagement
    gesture](https://w3c.github.io/pointerlock/#dfn-engagement-gesture) (e.g. a
    click or touch event) for the browser to allow this.
