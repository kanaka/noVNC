# 1. Internal Modules

The noVNC client is composed of several internal modules that handle
rendering, input, networking, etc. Each of the modules is designed to
be cross-browser and independent from each other.

Note however that the API of these modules is not guaranteed to be
stable, and this documentation is not maintained as well as the
official external API.


## 1.1 Module List

* __Keyboard__ (core/input/keyboard.js): Keyboard input event handler with
non-US keyboard support. Translates keyDown and keyUp events to X11
keysym values.

* __Display__ (core/display.js): Efficient 2D rendering abstraction
layered on the HTML5 canvas element.

* __Clipboard__ (core/clipboard.js): Clipboard event handler.

* __Websock__ (core/websock.js): Websock client from websockify
with transparent binary data support.
[Websock API](https://github.com/novnc/websockify-js/wiki/websock.js) wiki page.


## 1.2 Callbacks

For the Mouse, Keyboard, Display and Clipboard objects the callback functions are
assigned to configuration attributes, just as for the RFB object. The
WebSock module has a method named 'on' that takes two parameters: the
callback event name, and the callback function.

## 2. Modules

## 2.1 Keyboard Module

### 2.1.1 Configuration Attributes

None

### 2.1.2 Methods

| name   | parameters | description
| ------ | ---------- | ------------
| grab   | ()         | Begin capturing keyboard events
| ungrab | ()         | Stop capturing keyboard events

### 2.1.3 Callbacks

| name       | parameters           | description
| ---------- | -------------------- | ------------
| onkeypress | (keysym, code, down) | Handler for key press/release


## 2.2 Display Module

### 2.2.1 Configuration Attributes

| name         | type  | mode | default | description
| ------------ | ----- | ---- | ------- | ------------
| scale        | float | RW   | 1.0     | Display area scale factor 0.0 - 1.0
| clipViewport | bool  | RW   | false   | Use viewport clipping
| width        | int   | RO   |         | Display area width
| height       | int   | RO   |         | Display area height

### 2.2.2 Methods

| name               | parameters                                              | description
| ------------------ | ------------------------------------------------------- | ------------
| viewportChangePos  | (deltaX, deltaY)                                        | Move the viewport relative to the current location
| viewportChangeSize | (width, height)                                         | Change size of the viewport
| absX               | (x)                                                     | Return X relative to the remote display
| absY               | (y)                                                     | Return Y relative to the remote display
| resize             | (width, height)                                         | Set width and height
| flip               | (from_queue)                                            | Update the visible canvas with the contents of the rendering canvas
| pending            | ()                                                      | Check if there are waiting items in the render queue
| flush              | ()                                                      | Resume processing the render queue unless it's empty
| fillRect           | (x, y, width, height, color, from_queue)                | Draw a filled in rectangle
| copyImage          | (old_x, old_y, new_x, new_y, width, height, from_queue) | Copy a rectangular area
| imageRect          | (x, y, width, height, mime, arr)                        | Draw a rectangle with an image
| blitImage          | (x, y, width, height, arr, offset, from_queue)          | Blit pixels (of R,G,B,A) to the display
| drawImage          | (img, x, y)                                             | Draw image and track damage
| autoscale          | (containerWidth, containerHeight)                       | Scale the display

### 2.2.3 Callbacks

| name    | parameters | description
| ------- | ---------- | ------------
| onflush | ()         | A display flush has been requested and we are now ready to resume FBU processing


## 2.4 Clipboard Module

### 2.4.1 Configuration Attributes

None

### 2.4.2 Methods

| name               | parameters        | description
| ------------------ | ----------------- | ------------
| grab               | ()                | Begin capturing clipboard events
| ungrab             | ()                | Stop capturing clipboard events

### 2.3.3 Callbacks

| name    | parameters | description
| ------- | ---------- | ------------
| onpaste | (text)     | Called with the text content of the clipboard when the user paste something
