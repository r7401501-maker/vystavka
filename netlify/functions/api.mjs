// API «Выставки проектов» для Netlify: функция + хранилище Netlify Blobs.
import {getStore} from "@netlify/blobs";
import {randomBytes,scrypt,createHash,timingSafeEqual} from "node:crypto";

const CATS=["ИИ","Игры","Дизайн","Образование","Наука","Экология","Здоровье","Недвижимость","Другое"];
const STAGES=["Идея","Прототип","MVP","Первые клиенты","Рост"];
const SEEK=["Пока ничего","Команду","Ментора","Тестеров","Фидбек","Инвестиции"];
const LOGIN=/^[\p{L}\p{N}_.-]{3,20}$/u,DAY=864e5;

const json=(code,obj,h={})=>new Response(JSON.stringify(obj),{status:code,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",...h}});
const fail=(code,msg)=>Object.assign(new Error(msg),{code});
const clip=(v,n)=>String(v==null?"":v).trim().slice(0,n);
const th=t=>createHash("sha256").update(t).digest("hex");
const hash=(pw,salt)=>new Promise((ok,no)=>scrypt(pw,salt,32,(e,k)=>e?no(e):ok(k.toString("hex"))));
const enc=encodeURIComponent;
const cookies=req=>Object.fromEntries((req.headers.get("cookie")||"").split(";").map(s=>s.trim().split("=")).filter(a=>a[0]).map(a=>[a[0],a.slice(1).join("=")]));
async function body(req){const t=await req.text();if(t.length>30000)throw fail(413,"Слишком большой запрос");try{const o=JSON.parse(t||"{}");return o&&typeof o==="object"?o:{}}catch(e){throw fail(400,"Неверный запрос")}}

async function me(S,req){const t=cookies(req).vt;if(!t)return null;const s=await S.get("s/"+th(t),{type:"json"});if(!s||s.exp<Date.now())return null;const u=await S.get("u/"+enc(s.login),{type:"json"});return u?{uid:u.uid,name:u.name}:null}
async function start(S,req,u){const t=randomBytes(32).toString("hex");await S.setJSON("s/"+th(t),{login:u.login,exp:Date.now()+30*DAY});
  const secure=new URL(req.url).protocol==="https:";
  return{"Set-Cookie":"vt="+t+"; Path=/; HttpOnly; SameSite=Lax; Max-Age="+30*86400+(secure?"; Secure":"")}}
async function limited(S,req){const ip=(req.headers.get("x-nf-client-connection-ip")||req.headers.get("x-forwarded-for")||"?").split(",")[0].trim();
  const k="r/"+enc(ip)+"/"+Math.floor(Date.now()/6e4),n=+(await S.get(k)||0);if(n>=15)return true;await S.set(k,String(n+1));return false}

async function register(S,req){
  const b=await body(req),login=clip(b.login,40),pw=String(b.password||""),email=clip(b.email,100);
  if(!LOGIN.test(login))return json(400,{error:"Логин: 3–20 символов, буквы, цифры, _ . -"});
  if(pw.length<6||pw.length>100)return json(400,{error:"Пароль: от 6 до 100 символов"});
  if(email&&(email.length>80||!/^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$/.test(email)))return json(400,{error:"Проверьте адрес почты"});
  if(b.consent!==true)return json(400,{error:"Нужно согласие на обработку данных"});
  const k=login.toLowerCase(),key="u/"+enc(k);
  if(await S.get(key))return json(409,{error:"Такой логин уже занят"});
  const salt=randomBytes(16).toString("hex"),u={login:k,uid:"u"+randomBytes(6).toString("hex"),name:login,email,salt,h:await hash(pw,salt),ts:Date.now()};
  await S.setJSON(key,u);
  return json(200,{user:{uid:u.uid,name:u.name}},await start(S,req,u));
}
async function loginH(S,req){
  const b=await body(req),k=clip(b.login,40).toLowerCase(),pw=String(b.password||"").slice(0,100),u=await S.get("u/"+enc(k),{type:"json"});
  const h=await hash(pw,u?u.salt:"0".repeat(32));
  if(!u||!timingSafeEqual(Buffer.from(h),Buffer.from(u.h)))return json(401,{error:"Неверный логин или пароль"});
  return json(200,{user:{uid:u.uid,name:u.name}},await start(S,req,u));
}
function clean(b,u){const link=clip(b.link,300);return{name:clip(b.name,60),pitch:clip(b.pitch,120),cat:CATS.includes(b.cat)?b.cat:"Другое",stage:STAGES.includes(b.stage)?b.stage:"Идея",founder:clip(b.founder,60)||u.name,contact:clip(b.contact,80),desc:clip(b.desc,600),link:/^https?:\/\/\S+$/i.test(link)?link:"",seek:SEEK.includes(b.seek)?b.seek:"",uid:u.uid}}

export default async(req)=>{
  try{
    const S=getStore({name:"vystavka",consistency:"strong"}),p=new URL(req.url).pathname.replace(/\/+$/,""),m=req.method;
    if(p==="/api/health")return json(200,{status:"ok"});
    if(p==="/api/me"&&m==="GET"){const u=await me(S,req);return u?json(200,{user:u}):json(401,{error:"Вы не вошли"})}
    if(p==="/api/logout"&&m==="POST"){const t=cookies(req).vt;if(t)await S.delete("s/"+th(t));return json(200,{},{"Set-Cookie":"vt=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"})}
    if((p==="/api/register"||p==="/api/login")&&m==="POST"){if(await limited(S,req))return json(429,{error:"Слишком много попыток. Подождите минуту"});return p==="/api/register"?register(S,req):loginH(S,req)}
    if(p==="/api/projects"&&m==="GET"){
      const{blobs}=await S.list({prefix:"p/"});
      const items=(await Promise.all(blobs.slice(0,300).map(b=>S.get(b.key,{type:"json"})))).filter(Boolean).sort((a,b)=>b.ts-a.ts).slice(0,200);
      return json(200,{items});
    }
    if(p==="/api/projects"&&m==="POST"){
      const u=await me(S,req);if(!u)return json(401,{error:"Войдите, чтобы добавить проект"});
      const s=clean(await body(req),u);if(!s.name||!s.pitch)return json(400,{error:"Укажите название и описание одной строкой"});
      if((await S.list({prefix:"p/"+u.uid+"/"})).blobs.length>=20)return json(400,{error:"Можно добавить не больше 20 проектов"});
      s.id="p"+Date.now().toString(36)+randomBytes(3).toString("hex");s.ts=Date.now();
      await S.setJSON("p/"+u.uid+"/"+s.id,s);return json(200,{item:s});
    }
    const d=p.match(/^\/api\/projects\/([^/]+)$/);
    if(d&&m==="DELETE"){
      const u=await me(S,req);if(!u)return json(401,{error:"Войдите в аккаунт"});
      const id=decodeURIComponent(d[1]);if(!/^p[a-z0-9]{6,30}$/.test(id))return json(404,{error:"Проект не найден"});
      const key="p/"+u.uid+"/"+id;if(!(await S.get(key)))return json(404,{error:"Проект не найден или он не ваш"});
      await S.delete(key);return json(200,{});
    }
    return json(404,{error:"Не найдено"});
  }catch(e){if(e.code)return json(e.code,{error:e.message});console.error(e);return json(500,{error:"Ошибка сервера"})}
};
export const config={path:"/api/*"};
