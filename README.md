mutter-monorepo/
├── README.md (this file)
├── server/
│   ├── package.json
│   ├── server.js
│   ├── config.js
│   ├── models/User.js
│   ├── models/Post.js
│   ├── routes/auth.js
│   ├── routes/posts.js
│   ├── routes/payments.js
│   └── uploads/    (uploaded files)
└── client/
    ├── package.json
    ├── index.html
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── components/
        │   ├── Login.jsx
        │   ├── Register.jsx
        │   ├── Feed.jsx
        │   ├── PostComposer.jsx
        │   ├── Chat.jsx
        │   ├── LiveRoom.jsx
        │   └── Profile.jsx
        └── styles.css{
  "name": "mutter-server",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "cors": "^2.8.5",
    "dotenv": "^16.0.0",
    "express": "^4.18.2",
    "express-rate-limit": "^6.7.0",
    "helmet": "^7.0.0",
    "jsonwebtoken": "^9.0.0",
    "mongoose": "^7.0.0",
    "multer": "^1.4.5-lts.1",
    "socket.io": "^4.7.0",
    "stripe": "^12.0.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  }
}require('dotenv').config();
module.exports = {
  PORT: process.env.PORT || 4000,
  MONGO_URI: process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/mutter',
  JWT_SECRET: process.env.JWT_SECRET || 'change_this_secret',
  CLIENT_URL: process.env.CLIENT_URL || 'http://localhost:5173',
  STRIPE_SECRET: process.env.STRIPE_SECRET || ''
};const mongoose = require('mongoose');
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  bio: String,
  avatarUrl: String,
  createdAt: { type: Date, default: Date.now },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  balance: { type: Number, default: 0 },
  banned: { type: Boolean, default: false }
});
module.exports = mongoose.model('User', UserSchema);const mongoose = require('mongoose');
const PostSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: String,
  mediaUrl: String,
  mediaType: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  flagged: { type: Boolean, default: false }
});
module.exports = mongoose.model('Post', PostSchema);const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { JWT_SECRET } = require('../config');

// register
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Missing fields' });
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: 'Email exists' });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash: hash });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const Post = require('../models/Post');
const User = require('../models/User');

// storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, 'uploads/'); },
  filename: function (req, file, cb) { cb(null, Date.now() + '-' + file.originalname); }
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    // allow images & video
    const allowed = /jpeg|jpg|png|gif|mp4|mov|webm/;
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.test(ext)) cb(null, true); else cb(new Error('Unsupported file type'));
  }
});

// create post
router.post('/', upload.single('media'), async (req, res) => {
  try {
    // basic profanity check on text
    const text = req.body.text || '';
    const profane = /(sex|fuck|shit|porn|nigger)/i;
    if (profane.test(text)) return res.status(400).json({ message: 'Inappropriate content' });

    const mediaUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const mediaType = req.file ? req.file.mimetype : null;
    const post = await Post.create({ author: req.body.userId, text, mediaUrl, mediaType });
    res.json(post);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to create post' });
  }
});

// get feed
router.get('/', async (req, res) => {
  const posts = await Post.find().sort({ createdAt: -1 }).populate('author', 'name avatarUrl');
  res.json(posts);
});

// flag post
router.post('/:id/flag', async (req, res) => {
  await Post.findByIdAndUpdate(req.params.id, { flagged: true });
  res.json({ ok: true });
});

module.exports = router;const express = require('express');
const router = express.Router();
const { STRIPE_SECRET } = require('../config');
const stripe = require('stripe')(STRIPE_SECRET || '');

// create a payment intent (demo only)
router.post('/create-intent', async (req, res) => {
  const { amount } = req.body; // cents
  // In production, validate user, amount, currency
  try {
    if (!STRIPE_SECRET) return res.status(500).json({ message: 'Stripe not configured' });
    const intent = await stripe.paymentIntents.create({ amount, currency: 'usd' });
    res.json({ clientSecret: intent.client_secret });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Stripe error' });
  }
});

module.exports = router;const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');

const { PORT, MONGO_URI, CLIENT_URL, JWT_SECRET } = require('./config');
const authRoutes = require('./routes/auth');
const postsRoutes = require('./routes/posts');
const paymentsRoutes = require('./routes/payments');

mongoose.connect(MONGO_URI).then(() => console.log('Mongo connected'));

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: CLIENT_URL } });

app.use(helmet());
app.use(cors({ origin: CLIENT_URL }));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// rate limiter
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// api
app.use('/api/auth', authRoutes);
app.use('/api/posts', postsRoutes);
app.use('/api/payments', paymentsRoutes);

// simple health
app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// Socket.io: chat + signaling for WebRTC
io.on('connection', (socket) => {
  console.log('socket connected', socket.id);

  // Join room and notify others with socket id (so we can target peer-to-peer signals)
  socket.on('join-room', (roomId, userId) => {
    socket.join(roomId);
    // send the join event to others with the new user's socket id
    socket.to(roomId).emit('user-joined', { userId, socketId: socket.id });
  });

  // generic signal forwarder expects { to: targetSocketId, from: socket.id, data }
  socket.on('signal', ({ to, from, data }) => {
    io.to(to).emit('signal', { from, data });
  });

  // chat broadcast
  socket.on('chat-message', (payload) => {
    const { roomId, message } = payload;
    io.to(roomId).emit('chat-message', payload);
  });

  socket.on('disconnect', () => console.log('disconnected', socket.id));
});

server.listen(PORT, () => console.log('Server listening on', PORT));{
  "name": "mutter-client",
  "private": true,
  "version": "1.0.0",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "axios": "^1.4.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "socket.io-client": "^4.7.0",
    "jwt-decode": "^3.1.2"
  },
  "devDependencies": {
    "vite": "^5.0.0",
    "tailwindcss": "^4.4.0",
    "postcss": "^8.4.0",
    "autoprefixer": "^10.4.0"
  }
}import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './styles.css'

createRoot(document.getElementById('root')).render(<App />)import React, { useEffect, useState } from 'react'
import axios from 'axios'
import io from 'socket.io-client'

const API = import.meta.env.VITE_API_URL || 'http://localhost:4000/api'
const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || 'http://localhost:4000'

const socket = io(SOCKET_URL, { autoConnect: false })

export default function App(){
  const [token, setToken] = useState(localStorage.getItem('token'))
  const [view, setView] = useState('feed')

  useEffect(()=>{
    if(token) socket.auth = { token }, socket.connect();
  }, [token])

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <header className="mb-4">
        <h1 className="text-2xl font-bold">Mutter</h1>
        <nav className="space-x-2">
          <button onClick={()=>setView('feed')}>Feed</button>
          <button onClick={()=>setView('live')}>Live</button>
          <button onClick={()=>setView('chat')}>Chat</button>
          <button onClick={()=>setView('profile')}>Profile</button>
        </nav>
      </header>

      <main>
        { !token ? <Auth onLogin={(t)=>{ setToken(t); localStorage.setItem('token', t); }} /> : (
          {
            feed: <Feed socket={socket} token={token} />,
            live: <LiveRoom socket={socket} token={token} />,
            chat: <Chat socket={socket} token={token} />,
            profile: <Profile token={token} />
          }[view]
        ) }
      </main>
    </div>
  )
}

// --- Auth --
function Auth({ onLogin }){
  const [mode, setMode] = useState('login')
  return (
    <div className="max-w-md">
      { mode === 'login' ? <Login onLogin={onLogin} switchMode={()=>setMode('register')} /> : <Register onRegister={onLogin} switchMode={()=>setMode('login')} /> }
    </div>
  )
}

function Login({ onLogin, switchMode }){
  const [email,setEmail]=useState(''); const [password,setPassword]=useState('');
  async function submit(e){ e.preventDefault(); try{ const res = await axios.post(`${API}/auth/login`, { email, password }); onLogin(res.data.token); }catch(err){ alert(err.response?.data?.message || 'Login failed') } }
  return (<form onSubmit={submit}><h2>Login</h2><input value={email} onChange={e=>setEmail(e.target.value)} placeholder="email"/><input value={password} onChange={e=>setPassword(e.target.value)} placeholder="password" type="password"/><button>Login</button><p onClick={switchMode}>Register</p></form>)
}

function Register({ onRegister, switchMode }){
  const [name,setName]=useState(''); const [email,setEmail]=useState(''); const [password,setPassword]=useState('');
  async function submit(e){ e.preventDefault(); try{ const res = await axios.post(`${API}/auth/register`, { name, email, password }); onRegister(res.data.token); }catch(err){ alert(err.response?.data?.message || 'Register failed') } }
  return (<form onSubmit={submit}><h2>Register</h2><input value={name} onChange={e=>setName(e.target.value)} placeholder="name"/><input value={email} onChange={e=>setEmail(e.target.value)} placeholder="email"/><input value={password} onChange={e=>setPassword(e.target.value)} placeholder="password" type="password"/><button>Register</button><p onClick={switchMode}>Login</p></form>)
}

// --- Feed component (simplified)
function Feed({ socket, token }){
  const [posts,setPosts] = useState([])
  useEffect(()=>{ axios.get(`${API}/posts`).then(r=>setPosts(r.data)) }, [])
  return (<div><h2>Feed</h2><PostComposer token={token} onPosted={()=>axios.get(`${API}/posts`).then(r=>setPosts(r.data))} /><div>{posts.map(p=> (<div key={p._id} className="p-2 border mb-2"><b>{p.author?.name}</b><p>{p.text}</p>{p.mediaUrl && <div><a href={`${SOCKET_URL}${p.mediaUrl}`} target="_blank">media</a></div>}</div>))}</div></div>)
}

function PostComposer({ token, onPosted }){
  const [text,setText] = useState(''); const [file,setFile] = useState(null)
  async function submit(e){ e.preventDefault(); const fd = new FormData(); fd.append('text', text); fd.append('userId', 'me'); if(file) fd.append('media', file);
    try{ await axios.post(`${API}/posts`, fd, { headers: { 'Content-Type': 'multipart/form-data', Authorization: `Bearer ${token}` } }); setText(''); setFile(null); onPosted(); }catch(err){ alert(err.response?.data?.message || 'Post failed') } }
  return (<form onSubmit={submit}><textarea value={text} onChange={e=>setText(e.target.value)} placeholder="What's up?"/><input type="file" onChange={e=>setFile(e.target.files[0])}/><button>Post</button></form>)
}

// --- Chat placeholder
function Chat({ socket, token }){
  const [room, setRoom] = useState('global');
  const [messages, setMessages] = useState([]);
  const [msg, setMsg] = useState('');
  useEffect(()=>{
    socket.on('chat-message', (data)=> setMessages(m=>[...m, data]));
    socket.emit('join-room', room, 'me');
    return ()=>{ socket.off('chat-message'); }
  }, [room])
  function send(){ socket.emit('chat-message', { roomId: room, message: msg, from: 'me' }); setMsg(''); }
  return (<div><h2>Chat — {room}</h2><div style={{height:300,overflow:'auto'}}>{messages.map((m,i)=><div key={i}><b>{m.from}</b>: {m.message}</div>)}</div><input value={msg} onChange={e=>setMsg(e.target.value)} /><button onClick={send}>Send</button></div>)
}

// --- LiveRoom (Full one-to-one WebRTC signaling sample)
function LiveRoom({ socket, token }){
  const localRef = React.useRef();
  const [remotes, setRemotes] = React.useState([]); // array of { socketId, stream }
  const pcs = React.useRef({}); // map socketId -> RTCPeerConnection
  const localStreamRef = React.useRef(null);
  const ROOM_ID = 'main';

  useEffect(()=>{
    // handle someone joining the room (server sends their socketId)
    socket.on('user-joined', async ({ userId, socketId }) => {
      console.log('user-joined', userId, socketId);
      // create a peer connection and act as caller: create offer
      await createAndSendOffer(socketId);
    });

    // handle incoming signaling messages
    socket.on('signal', async ({ from, data }) => {
      if (!from || !data) return;
      let pc = pcs.current[from];
      if (data.type === 'offer'){
        // we are the callee
        if (!pc) pc = await preparePeerConnection(from);
        await pc.setRemoteDescription(new RTCSessionDescription(data));
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        socket.emit('signal', { to: from, from: socket.id, data: pc.localDescription });
      } else if (data.type === 'answer'){
        if (!pc) {
          console.warn('Received answer but no pc for', from); return;
        }
        await pc.setRemoteDescription(new RTCSessionDescription(data));
      } else if (data.candidate){
        if (!pc) { console.warn('No pc for candidate from', from); return; }
        try{ await pc.addIceCandidate(new RTCIceCandidate(data.candidate)); }catch(e){ console.error(e); }
      }
    });

    return ()=>{
      socket.off('user-joined'); socket.off('signal');
      // close all peer connections
      Object.values(pcs.current).forEach(pc=>pc.close()); pcs.current = {};
    }
  }, []);

  async function startLocal(){
    try{
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      localStreamRef.current = stream;
      localRef.current.srcObject = stream;
      localRef.current.muted = true;
      localRef.current.play().catch(()=>{});
      // join room so server notifies others
      socket.emit('join-room', ROOM_ID, 'me');
    }catch(err){ alert('Could not access camera/mic: ' + err.message) }
  }

  async function preparePeerConnection(remoteSocketId){
    const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });

    // send local ICE candidates to remote via server
    pc.onicecandidate = (e) => { if (e.candidate) socket.emit('signal', { to: remoteSocketId, from: socket.id, data: { candidate: e.candidate } }); };

    // when remote track arrives, store it
    pc.ontrack = (e) => {
      console.log('remote track from', remoteSocketId);
      setRemotes(prev=>{
        const exists = prev.find(r=>r.socketId===remoteSocketId);
        if (exists) return prev.map(r=> r.socketId===remoteSocketId ? { ...r, stream: e.streams[0] } : r );
        return [...prev, { socketId: remoteSocketId, stream: e.streams[0] }];
      });
    };

    // add local tracks
    if (!localStreamRef.current){
      try{ localStreamRef.current = await navigator.mediaDevices.getUserMedia({ video: true, audio: true }); localRef.current.srcObject = localStreamRef.current; localRef.current.muted = true; localRef.current.play().catch(()=>{}); }catch(e){ console.error('getUserMedia failed', e); }
    }
    localStreamRef.current.getTracks().forEach(t => pc.addTrack(t, localStreamRef.current));

    pcs.current[remoteSocketId] = pc;
    return pc;
  }

  async function createAndSendOffer(remoteSocketId){
    const pc = await preparePeerConnection(remoteSocketId);
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    // send offer SDP to remote through server
    socket.emit('signal', { to: remoteSocketId, from: socket.id, data: pc.localDescription });
  }

  return (
    <div>
      <h2>Live — One-to-one demo</h2>
      <div className="flex gap-4">
        <div>
          <h3>You</h3>
          <video ref={localRef} width={320} height={240} autoPlay playsInline className="border" />
        </div>
        <div>
          <h3>Remote</h3>
          <div style={{display:'grid',gridTemplateColumns:'repeat(2,1fr)',gap:8}}>
            {remotes.map(r=> (
              <VideoPlayer key={r.socketId} stream={r.stream} />
            ))}
          </div>
        </div>
      </div>
      <div className="mt-2">
        <button onClick={startLocal}>Start / Go Live</button>
      </div>
    </div>
  )
}

function VideoPlayer({ stream }){
  const ref = React.useRef();
  useEffect(()=>{ if (stream && ref.current){ ref.current.srcObject = stream; ref.current.play().catch(()=>{}); } }, [stream]);
  return <video ref={ref} width={240} height={180} autoPlay playsInline className="border" />
}

function Profile(){ return <div><h2>Profile</h2><p>Profile & payments integration go here</p></div> } return <div><h2>Profile</h2><p>Profile & payments integration go here</p></div> }@tailwind base; @tailwind components; @tailwind utilities;
html,body,#root{height:100%}# Mutter-full-application-
Mutter application 
