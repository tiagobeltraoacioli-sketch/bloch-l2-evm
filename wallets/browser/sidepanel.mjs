// SPDX-License-Identifier: MIT OR Apache-2.0
// Playwright does not expose Chrome sidepanel targets as Page objects. Attach
// over the same browser's CDP pipe and interact with visible DOM using real input.
export async function attachPanel(browserSession, targetId) {
  await browserSession.send('Target.activateTarget',{targetId});
  const {sessionId}=await browserSession.send('Target.attachToTarget',{targetId,flatten:false});
  let sequence=0;
  const pending=new Map();
  const receive=event=>{
    if(event.sessionId!==sessionId)return;
    const message=JSON.parse(event.message);
    const request=pending.get(message.id);
    if(!request)return;
    pending.delete(message.id);clearTimeout(request.timer);
    if(message.error)request.reject(Error(JSON.stringify(message.error)));else request.resolve(message.result);
  };
  const detached=event=>{if(event.sessionId!==sessionId)return;for(const request of pending.values()){clearTimeout(request.timer);request.reject(Error('panel target detached'));}pending.clear();};
  browserSession.on('Target.receivedMessageFromTarget',receive);
  browserSession.on('Target.detachedFromTarget',detached);
  const send=(method,params={})=>new Promise((resolve,reject)=>{
    const id=++sequence;
    const timer=setTimeout(()=>{pending.delete(id);reject(Error(`sidepanel CDP timeout: ${method}`));},10000);
    pending.set(id,{resolve,reject,timer});
    browserSession.send('Target.sendMessageToTarget',{sessionId,message:JSON.stringify({id,method,params})}).catch(error=>{
      pending.delete(id);clearTimeout(timer);reject(error);
    });
  });
  let executionContextId;
  async function evaluate(expression){
    if(executionContextId===undefined){
    const {frameTree}=await send('Page.getFrameTree');
    ({executionContextId}=await send('Page.createIsolatedWorld',{frameId:frameTree.frame.id,worldName:'bloch-synthetic-ui'}));
    }
    const result=await send('Runtime.evaluate',{contextId:executionContextId,expression,returnByValue:true});
    if(result.exceptionDetails)throw Error(result.exceptionDetails.text);
    return result.result.value;
  }
  return {
    text:()=>evaluate('document.body?.innerText ?? ""'),
    async click(name){
      const point=await evaluate(`(()=>{const matches=[...document.querySelectorAll('button')].filter(b=>b.innerText.trim()===${JSON.stringify(name)}&&!b.disabled&&b.getBoundingClientRect().width>0);if(matches.length!==1)return null;const b=matches[0];b.scrollIntoView({block:'center'});const r=b.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()`);
      if(!point)return false;
      await send('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...point});
      await send('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...point});
      return true;
    },
    async close(){browserSession.off('Target.receivedMessageFromTarget',receive);browserSession.off('Target.detachedFromTarget',detached);for(const request of pending.values()){clearTimeout(request.timer);request.reject(Error('panel detached'));}pending.clear();await Promise.race([browserSession.send('Target.detachFromTarget',{sessionId}).catch(()=>{}),new Promise(resolve=>setTimeout(resolve,1000))]);},
  };
}
