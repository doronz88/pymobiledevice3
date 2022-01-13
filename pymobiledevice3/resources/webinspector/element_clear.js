function(element){"use strict";function isEditable(element){if(element.disabled||element.readOnly)
return false;if(element instanceof HTMLTextAreaElement)
return true;if(element.isContentEditable)
return true;if(element.tagName.toUpperCase()!="INPUT")
return false;switch(element.type){case"color":case"date":case"datetime-local":case"email":case"file":case"month":case"number":case"password":case"range":case"search":case"tel":case"text":case"time":case"url":case"week":return true;}
return false;}
if(!isEditable(element))
throw{name:"InvalidElementState",message:"Element must be user-editable in order to clear."};if(element.isContentEditable){if(element.innerHTML==="")
return;element.focus();element.innerHTML="";element.blur();return;}
function isResettableElementEmpty(element){if(element instanceof HTMLInputElement&&element.type=="file")
return element.files.length==0;return element.value==="";}
if(element.validity.valid&&isResettableElementEmpty(element))
return;element.focus();element.value="";var event=document.createEvent("Event");event.initEvent("change",true,true);element.dispatchEvent(event);element.blur();}
//# sourceURL=__InjectedScript_WDFormElementClear.js
// sourceURL=__InjectedScript_WebDriver_FormElementClear.js
