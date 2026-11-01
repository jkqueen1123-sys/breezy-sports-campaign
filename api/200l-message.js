const crypto=require('crypto');
const zlib=require('zlib');
const WINDOW_MS=10*60*1000;
const MAX_ATTEMPTS_PER_IP=300;
const buckets=globalThis.__examMessageRateBuckets||(globalThis.__examMessageRateBuckets=new Map());

const openers=[
'The exam period starts tomorrow, {n}, and this is your moment to turn preparation into performance.',
'{n}, a new exam chapter begins tomorrow; walk into it with a calm mind and confidence in your effort.',
'Tomorrow is the start of your examinations, {n}. Take a breath, trust your preparation and give every paper your best.',
'{n}, you have made it to this point. Let tomorrow be the beginning of a focused and confident exam run.',
'As your examinations begin tomorrow, {n}, remember that steady thinking is just as important as what you have memorised.',
'{n}, the work you have put in deserves a fair chance. Give yourself that chance by staying calm and focused tomorrow.',
'Your 200L examinations begin tomorrow, {n}; meet the challenge one paper and one question at a time.',
'{n}, tomorrow you begin an important stretch. Leave panic behind and take the questions in front of you methodically.',
'A fresh exam season begins tomorrow, {n}. You do not need perfection; you need focus, courage and a good plan.',
'{n}, let tomorrow be a reminder of how far you have come and how much you are capable of doing.',
'With your examinations beginning tomorrow, {n}, make room for confidence, careful reading and sensible time management.',
'{n}, your next step starts tomorrow. Enter each paper prepared to think clearly, work carefully and keep going.',
'Tomorrow brings the first paper, {n}. Do not let the size of the whole exam period distract you from the question at hand.',
'{n}, this is your opportunity to show what you know. Keep your head clear and make every minute count.',
'As the 200L exams commence tomorrow, {n}, remember that composure can help you access the knowledge you already have.',
'{n}, your examination journey begins tomorrow. Give yourself the benefit of a rested mind and a deliberate start.'
];
const advice=[
'Read each question twice, underline the instruction and answer exactly what is being asked.',
'Begin with the questions you understand, secure those marks and return to the difficult ones with a fresh mind.',
'Watch the time without rushing; divide the paper into manageable sections and keep moving.',
'For theory questions, make a brief outline before writing so your answer stays organised and complete.',
'For MCQs, eliminate clearly incorrect options first, then compare the remaining choices against the stem.',
'Do not spend too long on one stubborn question; mark it, move on and revisit it later.',
'Use the final minutes to check skipped questions, numbering and any instructions you may have overlooked.',
'Keep your answers precise. A clear, relevant response is better than a long answer that drifts off topic.',
'Take a moment to settle before the paper starts; a calm beginning can steady the rest of your exam.',
'Revise the high-yield points, then stop and rest; a tired brain rarely rewards endless last-minute reading.',
'Listen carefully to invigilator instructions and confirm the required details before you begin writing.',
'When a question feels unfamiliar, identify its key concept and build your answer from the foundation you know.',
'Keep track of units, definitions and key terms; small details can make a strong answer more accurate.',
'Avoid comparing your pace with classmates. Stay with your own plan and the time available to you.',
'If anxiety rises, pause for a slow breath, reset your attention and take the next question step by step.',
'Sleep, hydrate and eat something sensible; looking after yourself is part of preparing well.'
];
const closers=[
'I am wishing you clarity, strength and excellent results throughout the papers.',
'May your effort meet opportunity, and may you finish each paper knowing you gave it your best.',
'Go in prepared, come out proud of the discipline you showed, and keep believing in yourself.',
'You have a whole class cheering each other on; take your place and do your best.',
'One paper at a time. Keep your focus, protect your confidence and finish strong.',
'May the questions be fair, your recall be sharp and your time management be solid.',
'Do not underestimate what consistent effort can achieve. I am rooting for you.',
'Wishing you a steady mind, clear answers and the satisfaction of a job well done.'
];
const nameNotes={
Beloved:'Let the reminder in your name stay with you: you are valued, and your hard work matters.',
Grace:'Carry the calm confidence your name suggests; you do not need to panic to perform well.',
Goodness:'Let the goodness in your name remind you to approach every paper with a clear and steady mind.',
Praise:'Let your name remind you to recognise your own progress, not only the final result.',
Favour:'May the word in your name remind you to stay hopeful while still trusting the preparation you have done.',
Testimony:'May this exam period become another chapter of growth you will be proud to tell.',
Precious:'Remember that your effort is valuable; give each paper your full attention, one question at a time.',
Joy:'Protect your joy through the exam period: stay focused, take breaks and do not let pressure define you.',
Patience:'Your name offers a useful exam reminder: be patient with each question and read before you answer.',
Success:'Let your name encourage you, but let your preparation and disciplined approach do the work.',
Delight:'Keep a little delight in the journey; progress is worth appreciating, even during demanding papers.',
Faith:'Hold on to faith in your preparation while making every answer deliberate and well considered.',
Blessing:'May you recognise the opportunity in front of you and approach it with gratitude and focus.',
Evidence:'Let your work be the evidence: trust what you have revised and express it clearly.',
Overcomer:'Meet difficult questions with resilience; one challenging moment does not determine the whole paper.',
Covenant:'Stay committed to your plan and keep your attention on the task in front of you.',
Convenant:'Stay committed to your plan and keep your attention on the task in front of you.',
Dominion:'Own your preparation with confidence, but remember to manage your time calmly.',
Victory:'Approach each paper with a quiet determination to give your best, whatever the questions look like.',
Smart:'Use your judgement well: read carefully, identify what is being tested and avoid rushing.',
Promise:'Treat each paper as an opportunity to fulfil the promise of the work you have put in.',
Bright:'Bring a clear mind into the hall; careful reading can turn what you know into marks.',
Peter:'Build your answers carefully: start with what is certain, then develop the rest logically.',
Samuel:'Let consistency be your strength: a calm, methodical approach will serve you throughout the paper.',
Daniel:'Stay composed under pressure; a structured answer is often stronger than a rushed one.',
Victor:'Step into each paper ready to compete with the questions, not with anyone else.',
Victoria:'Give yourself permission to work steadily; confidence grows as you handle each question well.',
Faithful:'Stay faithful to the process: prepare, read carefully, manage time and keep moving forward.',
Claire:'Keep your thinking clear and your answers direct; clarity is an advantage in any examination.'
};

function normalizeSurname(v){return String(v||'').normalize('NFKC').trim().replace(/\s+/g,' ').toLocaleLowerCase('en-US');}
function bodyOf(req){if(req.body&&typeof req.body==='object')return req.body;if(typeof req.body==='string'){try{return JSON.parse(req.body)}catch{return {}}}return {};}
function send(res,status,payload){res.status(status).setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store, max-age=0');res.setHeader('X-Content-Type-Options','nosniff');return res.end(JSON.stringify(payload));}
function decryptRecords(encoded,secret){
 const packed=Buffer.from(encoded,'base64');if(packed.length<29)throw new Error('Invalid dataset');
 const iv=packed.subarray(0,12),tag=packed.subarray(packed.length-16),ciphertext=packed.subarray(12,packed.length-16);
 const key=crypto.createHash('sha256').update(secret).digest();
 const decipher=crypto.createDecipheriv('aes-256-gcm',key,iv);decipher.setAuthTag(tag);
 const compressed=Buffer.concat([decipher.update(ciphertext),decipher.final()]);
 return JSON.parse(zlib.gunzipSync(compressed).toString('utf8'));
}
function renderMessage(firstName,index){
 const n=Number(index);if(!Number.isInteger(n)||n<0||n>=123)throw new Error('Invalid message index');
 const opener=openers[n%openers.length].replace('{n}',firstName);
 const note=nameNotes[firstName]||'Your name is uniquely yours, and so is the effort you have put into reaching this point. Let your preparation speak for you.';
 const tip=advice[(n*5+Math.floor(n/openers.length))%advice.length];
 const close=closers[(n*3+Math.floor(n/advice.length))%closers.length];
 return opener+' '+note+' '+tip+' '+close+' remember to vote for breezy';
}

module.exports=async function handler(req,res){
 if(req.method!=='POST'){res.setHeader('Allow','POST');return send(res,405,{ok:false,message:'Method not allowed.'});}
 const secret=process.env.EXAM_LOOKUP_SECRET,encrypted=process.env.EXAM_MESSAGES_ENC;
 if(!secret||!encrypted)return send(res,503,{ok:false,message:'Your personal messages are being prepared. Please check back shortly.'});
 const ip=String(req.headers['x-forwarded-for']||'').split(',')[0].trim()||'unknown';
 const ipKey=crypto.createHmac('sha256',secret).update(ip).digest('hex');
 const now=Date.now();let bucket=buckets.get(ipKey);
 if(!bucket||now-bucket.startedAt>WINDOW_MS)bucket={startedAt:now,count:0};
 bucket.count++;buckets.set(ipKey,bucket);
 if(buckets.size>2000)for(const [k,v] of buckets){if(now-v.startedAt>WINDOW_MS)buckets.delete(k);}
 if(bucket.count>MAX_ATTEMPTS_PER_IP)return send(res,429,{ok:false,message:'Too many attempts from this connection. Please wait a few minutes and try again.'});
 const body=bodyOf(req),surname=normalizeSurname(body.surname),card=String(body.cardNumber||'').trim();
 if(!surname||surname.length>60||!/^\d{4}$/.test(card))return send(res,400,{ok:false,message:'Enter your surname and exactly four matriculation digits.'});
 let records;try{records=decryptRecords(encrypted,secret)}catch{return send(res,503,{ok:false,message:'The message service is temporarily unavailable. Please try again shortly.'});}
 const key=crypto.createHmac('sha256',secret).update(surname+'|'+card).digest('hex').slice(0,32);
 const record=records[key];
 if(!record||typeof record.firstName!=='string'||!Number.isInteger(record.index))return send(res,404,{ok:false,message:'We could not match those details. Check the surname spelling and last four digits, then try again.'});
 try{return send(res,200,{ok:true,firstName:record.firstName,message:renderMessage(record.firstName,record.index)})}
 catch{return send(res,503,{ok:false,message:'The message service is temporarily unavailable. Please try again shortly.'});}
};