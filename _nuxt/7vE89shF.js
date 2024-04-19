import{_ as w}from"./Bfki6M5j.js";import{ab as $,S as p,O as r,o as P,a as N,ac as G,l as L,V as U,X as k,d as q,ad as I,ae as A,Y as M,Z as R,$ as T,a0 as c,af as V,b as s,R as b,w as _,a2 as f,n as v,f as y,c as D,t as E,a1 as J}from"./CaYY76c-.js";const X={base:"focus:outline-none focus-visible:outline-0 disabled:cursor-not-allowed disabled:opacity-75 flex-shrink-0",font:"font-medium",rounded:"rounded-md",truncate:"text-left break-all line-clamp-1",block:"w-full flex justify-center items-center",inline:"inline-flex items-center",size:{"2xs":"text-xs",xs:"text-xs",sm:"text-sm",md:"text-sm",lg:"text-sm",xl:"text-base"},gap:{"2xs":"gap-x-1",xs:"gap-x-1.5",sm:"gap-x-1.5",md:"gap-x-2",lg:"gap-x-2.5",xl:"gap-x-2.5"},padding:{"2xs":"px-2 py-1",xs:"px-2.5 py-1.5",sm:"px-2.5 py-1.5",md:"px-3 py-2",lg:"px-3.5 py-2.5",xl:"px-3.5 py-2.5"},square:{"2xs":"p-1",xs:"p-1.5",sm:"p-1.5",md:"p-2",lg:"p-2.5",xl:"p-2.5"},color:{white:{solid:"shadow-sm ring-1 ring-inset ring-gray-300 dark:ring-gray-700 text-gray-900 dark:text-white bg-white hover:bg-gray-50 disabled:bg-white dark:bg-gray-900 dark:hover:bg-gray-800/50 dark:disabled:bg-gray-900 focus-visible:ring-2 focus-visible:ring-primary-500 dark:focus-visible:ring-primary-400",ghost:"text-gray-900 dark:text-white hover:bg-white dark:hover:bg-gray-900 focus-visible:ring-inset focus-visible:ring-2 focus-visible:ring-primary-500 dark:focus-visible:ring-primary-400"},gray:{solid:"shadow-sm ring-1 ring-inset ring-gray-300 dark:ring-gray-700 text-gray-700 dark:text-gray-200 bg-gray-50 hover:bg-gray-100 disabled:bg-gray-50 dark:bg-gray-800 dark:hover:bg-gray-700/50 dark:disabled:bg-gray-800 focus-visible:ring-2 focus-visible:ring-primary-500 dark:focus-visible:ring-primary-400",ghost:"text-gray-700 dark:text-gray-200 hover:text-gray-900 dark:hover:text-white hover:bg-gray-50 dark:hover:bg-gray-800 focus-visible:ring-inset focus-visible:ring-2 focus-visible:ring-primary-500 dark:focus-visible:ring-primary-400",link:"text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 underline-offset-4 hover:underline focus-visible:ring-inset focus-visible:ring-2 focus-visible:ring-primary-500 dark:focus-visible:ring-primary-400"},black:{solid:"shadow-sm text-white dark:text-gray-900 bg-gray-900 hover:bg-gray-800 disabled:bg-gray-900 dark:bg-white dark:hover:bg-gray-100 dark:disabled:bg-white focus-visible:ring-inset focus-visible:ring-2 focus-visible:ring-primary-500 dark:focus-visible:ring-primary-400",link:"text-gray-900 dark:text-white underline-offset-4 hover:underline focus-visible:ring-inset focus-visible:ring-2 focus-visible:ring-primary-500 dark:focus-visible:ring-primary-400"}},variant:{solid:"shadow-sm text-white dark:text-gray-900 bg-{color}-500 hover:bg-{color}-600 disabled:bg-{color}-500 dark:bg-{color}-400 dark:hover:bg-{color}-500 dark:disabled:bg-{color}-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-{color}-500 dark:focus-visible:outline-{color}-400",outline:"ring-1 ring-inset ring-current text-{color}-500 dark:text-{color}-400 hover:bg-{color}-50 disabled:bg-transparent dark:hover:bg-{color}-950 dark:disabled:bg-transparent focus-visible:ring-2 focus-visible:ring-{color}-500 dark:focus-visible:ring-{color}-400",soft:"text-{color}-500 dark:text-{color}-400 bg-{color}-50 hover:bg-{color}-100 disabled:bg-{color}-50 dark:bg-{color}-950 dark:hover:bg-{color}-900 dark:disabled:bg-{color}-950 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-{color}-500 dark:focus-visible:ring-{color}-400",ghost:"text-{color}-500 dark:text-{color}-400 hover:bg-{color}-50 disabled:bg-transparent dark:hover:bg-{color}-950 dark:disabled:bg-transparent focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-{color}-500 dark:focus-visible:ring-{color}-400",link:"text-{color}-500 hover:text-{color}-600 disabled:text-{color}-500 dark:text-{color}-400 dark:hover:text-{color}-500 dark:disabled:text-{color}-400 underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-{color}-500 dark:focus-visible:ring-{color}-400"},icon:{base:"flex-shrink-0",loading:"animate-spin",size:{"2xs":"h-4 w-4",xs:"h-4 w-4",sm:"h-5 w-5",md:"h-5 w-5",lg:"h-5 w-5",xl:"h-6 w-6"}},default:{size:"sm",variant:"solid",color:"primary",loadingIcon:"i-heroicons-arrow-path-20-solid"}};function Y({ui:e,props:t}){const a=G();if($("ButtonGroupContextConsumer",!0),p("ButtonGroupContextConsumer",!1))return{size:r(()=>t.size),rounded:r(()=>e.value.rounded)};let n=a.parent,i;for(;n&&!i;){if(n.type.name==="ButtonGroup"){i=p(`group-${n.uid}`);break}n=n.parent}const l=r(()=>i==null?void 0:i.value.children.indexOf(a));return P(()=>{i==null||i.value.register(a)}),N(()=>{i==null||i.value.unregister(a)}),{size:r(()=>(i==null?void 0:i.value.size)||t.size),rounded:r(()=>!i||l.value===-1?e.value.rounded:i.value.children.length===1?i.value.ui.rounded:l.value===0?i.value.rounded.start:l.value===i.value.children.length-1?i.value.rounded.end:"rounded-none")}}const o=U(k.ui.strategy,k.ui.button,X),Z=q({components:{UIcon:w,ULink:I},inheritAttrs:!1,props:{...A,type:{type:String,default:"button"},block:{type:Boolean,default:!1},label:{type:String,default:null},loading:{type:Boolean,default:!1},disabled:{type:Boolean,default:!1},padded:{type:Boolean,default:!0},size:{type:String,default:()=>o.default.size,validator(e){return Object.keys(o.size).includes(e)}},color:{type:String,default:()=>o.default.color,validator(e){return[...k.ui.colors,...Object.keys(o.color)].includes(e)}},variant:{type:String,default:()=>o.default.variant,validator(e){return[...Object.keys(o.variant),...Object.values(o.color).flatMap(t=>Object.keys(t))].includes(e)}},icon:{type:String,default:null},loadingIcon:{type:String,default:()=>o.default.loadingIcon},leadingIcon:{type:String,default:null},trailingIcon:{type:String,default:null},trailing:{type:Boolean,default:!1},leading:{type:Boolean,default:!1},square:{type:Boolean,default:!1},truncate:{type:Boolean,default:!1},class:{type:[String,Object,Array],default:()=>""},ui:{type:Object,default:()=>({})}},setup(e,{slots:t}){const{ui:a,attrs:d}=M("button",R(e,"ui"),o),{size:n,rounded:i}=Y({ui:a,props:e}),l=r(()=>e.icon&&e.leading||e.icon&&!e.trailing||e.loading&&!e.trailing||e.leadingIcon),u=r(()=>e.icon&&e.trailing||e.loading&&e.trailing||e.trailingIcon),m=r(()=>e.square||!t.default&&!e.label),z=r(()=>{var h,x;const g=((x=(h=a.value.color)==null?void 0:h[e.color])==null?void 0:x[e.variant])||a.value.variant[e.variant];return T(c(a.value.base,a.value.font,i.value,a.value.size[n.value],a.value.gap[n.value],e.padded&&a.value[m.value?"square":"padding"][n.value],g==null?void 0:g.replaceAll("{color}",e.color),e.block?a.value.block:a.value.inline),e.class)}),B=r(()=>e.loading?e.loadingIcon:e.leadingIcon||e.icon),S=r(()=>e.loading&&!l.value?e.loadingIcon:e.trailingIcon||e.icon),O=r(()=>c(a.value.icon.base,a.value.icon.size[n.value],e.loading&&a.value.icon.loading)),j=r(()=>c(a.value.icon.base,a.value.icon.size[n.value],e.loading&&!l.value&&a.value.icon.loading)),C=r(()=>V(e));return{ui:a,attrs:d,isLeading:l,isTrailing:u,isSquare:m,buttonClass:z,leadingIconName:B,trailingIconName:S,leadingIconClass:O,trailingIconClass:j,linkProps:C}}});function F(e,t,a,d,n,i){const l=w,u=I;return s(),b(u,J({type:e.type,disabled:e.disabled||e.loading,class:e.buttonClass},{...e.linkProps,...e.attrs}),{default:_(()=>[f(e.$slots,"leading",{disabled:e.disabled,loading:e.loading},()=>[e.isLeading&&e.leadingIconName?(s(),b(l,{key:0,name:e.leadingIconName,class:v(e.leadingIconClass),"aria-hidden":"true"},null,8,["name","class"])):y("",!0)]),f(e.$slots,"default",{},()=>[e.label?(s(),D("span",{key:0,class:v([e.truncate?e.ui.truncate:""])},E(e.label),3)):y("",!0)]),f(e.$slots,"trailing",{disabled:e.disabled,loading:e.loading},()=>[e.isTrailing&&e.trailingIconName?(s(),b(l,{key:0,name:e.trailingIconName,class:v(e.trailingIconClass),"aria-hidden":"true"},null,8,["name","class"])):y("",!0)])]),_:3},16,["type","disabled","class"])}const Q=L(Z,[["render",F]]);export{Q as _,Y as u};
