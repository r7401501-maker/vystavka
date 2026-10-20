// API «Выставки проектов» для Netlify: функция + хранилище Netlify Blobs.
import {getStore} from "@netlify/blobs";
import {randomBytes,scrypt,createHash,timingSafeEqual} from "node:crypto";

const CATS=["ИИ","Игры","Дизайн","Образование","Наука","Экология","Здоровье","3D проекты","Другое"];
const STAGES=["Идея","Прототип","MVP","Первые клиенты","Рост"];
const SEEK=["Пока ничего","Команду","Ментора","Тестеров","Фидбек","Инвестиции"];
const LOGIN=/^[\p{L}\p{N}_.-]{3,20}$/u,DAY=864e5;
const STATUSES=["pending","approved","rejected"],MAX_PENDING=5;

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

// Админ: пароль берётся из переменной окружения ADMIN_PASSWORD (Netlify → Environment variables).
// Возвращает Response с ошибкой или null, если доступ разрешён.
async function adminGuard(S,req){
  const need=process.env.ADMIN_PASSWORD;
  if(!need||need.length<8)return json(503,{error:"Админка не настроена: добавьте ADMIN_PASSWORD (от 8 символов) в Netlify и запустите деплой заново"});
  const ip=(req.headers.get("x-nf-client-connection-ip")||req.headers.get("x-forwarded-for")||"?").split(",")[0].trim();
  const k="ra/"+enc(ip)+"/"+Math.floor(Date.now()/6e4),n=+(await S.get(k)||0);
  if(n>=10)return json(429,{error:"Слишком много попыток. Подождите минуту"});
  const got=th(String(req.headers.get("x-admin-password")||"").slice(0,200)),want=th(need);
  if(!timingSafeEqual(Buffer.from(got),Buffer.from(want))){await S.set(k,String(n+1));return json(401,{error:"Неверный пароль"})}
  return null;
}
async function listAll(S,max=500){
  const{blobs}=await S.list({prefix:"p/"});
  return(await Promise.all(blobs.slice(0,max).map(async b=>{const v=await S.get(b.key,{type:"json"});return v?{key:b.key,v}:null}))).filter(Boolean);
}

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
      const u=await me(S,req);
      // Старые проекты без поля status считаются опубликованными.
      const items=(await listAll(S,500)).map(x=>x.v).filter(v=>!v.status||v.status==="approved"||(u&&v.uid===u.uid)).sort((a,b)=>b.ts-a.ts).slice(0,200);
      return json(200,{items});
    }
    if(p==="/api/projects"&&m==="POST"){
      const u=await me(S,req);if(!u)return json(401,{error:"Войдите, чтобы добавить проект"});
      const s=clean(await body(req),u);if(!s.name||!s.pitch)return json(400,{error:"Укажите название и описание одной строкой"});
      const mine=(await S.list({prefix:"p/"+u.uid+"/"})).blobs;
      if(mine.length>=20)return json(400,{error:"Можно добавить не больше 20 проектов"});
      const mineV=(await Promise.all(mine.map(b=>S.get(b.key,{type:"json"})))).filter(Boolean);
      if(mineV.filter(v=>v.status==="pending").length>=MAX_PENDING)return json(400,{error:"У вас уже "+MAX_PENDING+" проектов на проверке. Дождитесь решения модератора"});
      s.id="p"+Date.now().toString(36)+randomBytes(3).toString("hex");s.ts=Date.now();
      s.status="pending";s.reason="";
      await S.setJSON("p/"+u.uid+"/"+s.id,s);return json(200,{status:"pending",item:s});
    }
    const d=p.match(/^\/api\/projects\/([^/]+)$/);
    if(d&&m==="DELETE"){
      const u=await me(S,req);if(!u)return json(401,{error:"Войдите в аккаунт"});
      const id=decodeURIComponent(d[1]);if(!/^p[a-z0-9]{6,30}$/.test(id))return json(404,{error:"Проект не найден"});
      const key="p/"+u.uid+"/"+id;if(!(await S.get(key)))return json(404,{error:"Проект не найден или он не ваш"});
      await S.delete(key);return json(200,{});
    }
    if(p==="/api/admin/projects"&&m==="GET"){
      const g=await adminGuard(S,req);if(g)return g;
      const items=(await listAll(S,500)).map(x=>({...x.v,status:x.v.status||"approved"})).sort((a,b)=>b.ts-a.ts);
      return json(200,{items});
    }
    const a=p.match(/^\/api\/admin\/projects\/([^/]+)$/);
    if(a&&(m==="POST"||m==="DELETE")){
      const g=await adminGuard(S,req);if(g)return g;
      const id=decodeURIComponent(a[1]);if(!/^p[a-z0-9]{6,30}$/.test(id))return json(404,{error:"Проект не найден"});
      const{blobs}=await S.list({prefix:"p/"});const hit=blobs.find(b=>b.key.split("/").pop()===id);
      if(!hit)return json(404,{error:"Проект не найден"});
      if(m==="DELETE"){await S.delete(hit.key);return json(200,{})}
      const b=await body(req),st=String(b.status||"");if(!STATUSES.includes(st))return json(400,{error:"Неверный статус"});
      const v=await S.get(hit.key,{type:"json"});if(!v)return json(404,{error:"Проект не найден"});
      v.status=st;v.reason=st==="rejected"?clip(b.reason,200):"";v.reviewed=Date.now();
      await S.setJSON(hit.key,v);return json(200,{item:v});
    }
    return json(404,{error:"Не найдено"});
  }catch(e){if(e.code)return json(e.code,{error:e.message});console.error(e);return json(500,{error:"Ошибка сервера"})}
};
export const config={path:"/api/*"};
