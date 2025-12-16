/*
 This inclues shared functionallity that multiple tools might need to
 allow users to easily start listening to and switch between
 different websockets.

 The idea is that there is a JSON file listing all avaliable websockets.
 This file is fetched by the websocket-picker and and the possible web
 sockets are shown to a tool user.
*/

var websockets;
var g_messageCallback;
var g_resetCallback;
var g_ws;

function switchWebsocket(url) {
  // close any eventually existing websockets
  if (g_ws) {
    g_ws.close();
  }
  // call the user supplied reset callback
  if (typeof g_resetCallback == "function") {
    g_resetCallback();
  }
  // open a new websocket
  g_ws = new WebSocket(url);
  g_ws.addEventListener("open", (e) => {
    console.log("connection opened to", url, ": ", e);
  });
  g_ws.addEventListener("message", g_messageCallback);
}

function drawWebsocketError(id) {
  let picker = document.getElementById(id);
  picker.style.padding = "1em";
  
  let alertDiv = document.createElement("div");
  alertDiv.classList.add("alert");
  alertDiv.classList.add("alert-warning");
  alertDiv.style.marginBottom = "0";
  
  let heading = document.createElement("strong");
  heading.textContent = "websockets.json not found";
  alertDiv.appendChild(heading);
  
  let br = document.createElement("br");
  alertDiv.appendChild(br);
  
  let text = document.createTextNode("The websocket picker requires a websockets.json file to be served alongside the HTML files. ");
  alertDiv.appendChild(text);
  
  let link = document.createElement("a");
  link.href = "https://github.com/peer-observer/peer-observer/blob/master/tools/websocket/README.md#websocket-picker";
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = "See documentation.";
  alertDiv.appendChild(link);
  
  picker.appendChild(alertDiv);
}

function drawWebsockets(id) {
  let picker = document.getElementById(id);
  picker.style.padding = "1em";
  let heading = document.createElement("h5");
  heading.textContent = "Nodes";
  picker.appendChild(heading);

  for (websocket in websockets) {
    let radio = document.createElement("input");
    radio.id = "radio-" + websocket;
    radio.name = "websocket-picker";
    radio.type = "radio";
    radio.value = websocket;
    radio.label = radio;
    radio.classList.add("form-check-input");

    let label = document.createElement("label");
    label.for = "radio-" + websocket;
    label.innerText = websocket;
    label.classList.add("form-check-label");

    radio.addEventListener("change", (e) => {
      let url = websockets[e.srcElement.value];
      switchWebsocket(url);
    });

    let wrapper = document.createElement("div");
    wrapper.style = "";
    wrapper.classList.add("form-check");
    wrapper.classList.add("form-check-inline");
    wrapper.appendChild(radio);
    wrapper.appendChild(label);
    picker.appendChild(wrapper);
  }
}

/*
 params:
  websocketJsonUrl: the url to the websocket.json file 
  divId: the id of the div where the picker should be placed in
  messageCallback: function called when a new message arrives
  resetCallback: function called when we switch websockets; should reset state
*/
function initWebsocketPicker(
  websocketJsonUrl,
  divId,
  messageCallback,
  resetCallback
) {
  const websocketJsonReq = new Request(websocketJsonUrl);
  g_messageCallback = messageCallback;
  g_resetCallback = resetCallback;

  fetch(websocketJsonReq)
    .then((response) => {
      if (!response.ok) {
        if (response.status === 404) {
          console.error("websockets.json file not found (404)!");
          drawWebsocketError(divId);
        } else {
          console.error("could not fetch websockets.json: HTTP", response.status);
          websockets = {};
          drawWebsockets(divId);
        }
        return;
      }
      return response.json();
    })
    .then((data) => {
      if (data) {
        console.log("learned about the following websockets:", data);
        websockets = data;
        drawWebsockets(divId);
      }
    })
    .catch((e) => {
      console.error("could not fetch websockets", e);
      websockets = {};
      drawWebsockets(divId);
    });
}
