function enterFullscreen(){let callback=arguments[0];if(!document.webkitFullscreenEnabled){callback(false);return;}
if(document.webkitIsFullScreen){callback(true);return;}
let fullscreenChangeListener,fullscreenErrorListener;fullscreenChangeListener=(e)=>{if(e.target!==document.documentElement)
return;if(!document.webkitIsFullScreen)
return;document.removeEventListener("webkitfullscreenerror",fullscreenChangeListener);document.documentElement.removeEventListener("webkitfullscreenchange",fullscreenErrorListener);callback(true);};fullscreenErrorListener=(e)=>{if(e.target!==document.documentElement)
return;document.removeEventListener("webkitfullscreenchange",fullscreenChangeListener);document.documentElement.removeEventListener("webkitfullscreenerror",fullscreenErrorListener);callback(!!document.webkitIsFullScreen);};document.addEventListener("webkitfullscreenchange",fullscreenChangeListener);document.documentElement.addEventListener("webkitfullscreenerror",fullscreenErrorListener);document.documentElement.webkitRequestFullscreen();}
//# sourceURL=__InjectedScript_WDEnterFullscreen.js
