function(strategy,ancestorElement,query,firstResultOnly,timeoutDuration,callback){ancestorElement=ancestorElement||document;switch(strategy){case"id":strategy="css selector";query="[id=\""+escape(query)+"\"]";break;case"name":strategy="css selector";query="[name=\""+escape(query)+"\"]";break;}
switch(strategy){case"css selector":case"link text":case"partial link text":case"tag name":case"class name":case"xpath":break;default:
 throw{name:"InvalidParameter",message:("Unsupported locator strategy: "+strategy+".")};}
function escape(string){return string.replace(/\\/g,"\\\\").replace(/"/g,"\\\"");}
function tryToFindNode(){try{switch(strategy){case"css selector":if(firstResultOnly)
return ancestorElement.querySelector(query)||null;return Array.from(ancestorElement.querySelectorAll(query));case"link text":let linkTextResult=[];for(let link of ancestorElement.getElementsByTagName("a")){if(link.text.trim()==query){linkTextResult.push(link);if(firstResultOnly)
break;}}
if(firstResultOnly)
return linkTextResult[0]||null;return linkTextResult;case"partial link text":let partialLinkResult=[];for(let link of ancestorElement.getElementsByTagName("a")){if(link.text.includes(query)){partialLinkResult.push(link);if(firstResultOnly)
break;}}
if(firstResultOnly)
return partialLinkResult[0]||null;return partialLinkResult;case"tag name":let tagNameResult=ancestorElement.getElementsByTagName(query);if(firstResultOnly)
return tagNameResult[0]||null;return Array.from(tagNameResult);case"class name":let classNameResult=ancestorElement.getElementsByClassName(query);if(firstResultOnly)
return classNameResult[0]||null;return Array.from(classNameResult);case"xpath":if(firstResultOnly){let xpathResult=document.evaluate(query,ancestorElement,null,XPathResult.FIRST_ORDERED_NODE_TYPE,null);if(!xpathResult)
return null;return xpathResult.singleNodeValue;}
let xpathResult=document.evaluate(query,ancestorElement,null,XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,null);if(!xpathResult||!xpathResult.snapshotLength)
return[];let arrayResult=[];for(let i=0;i<xpathResult.snapshotLength;++i)
arrayResult.push(xpathResult.snapshotItem(i));return arrayResult;}}catch(error){
 throw{name:"InvalidSelector",message:error.message};}}
const pollInterval=50;let pollUntil=performance.now()+timeoutDuration;function pollForNode(){let result=tryToFindNode();if(typeof result==="string"||result instanceof Node||(result instanceof Array&&result.length)){callback(result);return;}
let durationRemaining=pollUntil-performance.now();if(durationRemaining<pollInterval){callback(firstResultOnly?null:[]);return;}
setTimeout(pollForNode,pollInterval);}
pollForNode();}
//# sourceURL=__InjectedScript_WDFindNodes.js
