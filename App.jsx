import React, { useState } from 'react';
import axios from 'axios';

const API = import.meta.env.VITE_API_URL || 'http://localhost:5000';

export default function App(){
  const [view, setView] = useState('welcome');
  const [email,setEmail] = useState('');
  const [password,setPassword] = useState('');
  const [token,setToken] = useState(localStorage.getItem('mp_token')||'');
  const [amount,setAmount] = useState(1);
  const [card,setCard] = useState('4111111111111111');
  const [txs,setTxs] = useState([]);
  const [message,setMessage] = useState('');

  async function register(){
    try{
      await axios.post(API + '/api/register', { email, password, name: email.split('@')[0] });
      setMessage('Registered — now login');
    }catch(e){ setMessage(e.response?.data?.error || String(e)); }
  }
  async function login(){
    try{
      const r = await axios.post(API + '/api/login', { email, password });
      setToken(r.data.token);
      localStorage.setItem('mp_token', r.data.token);
      setMessage('Logged in');
    }catch(e){ setMessage(e.response?.data?.error || String(e)); }
  }
  async function pay(){
    try{
      const r = await axios.post(API + '/api/pay', { amount: Number(amount), cardNumber: card }, { headers: { Authorization: 'Bearer ' + token } });
      setMessage(JSON.stringify(r.data));
    }catch(e){ setMessage(e.response?.data?.error || String(e)); }
  }
  async function loadTxs(){
    try{
      const r = await axios.get(API + '/api/transactions', { headers: { Authorization: 'Bearer ' + token } });
      setTxs(r.data);
    }catch(e){ setMessage(e.response?.data?.error || String(e)); }
  }

  return (<div style={{ fontFamily:'Arial', padding:20, maxWidth:800, margin:'auto' }}>
    <h1>Millo Pay — Demo</h1>
    <p style={{ color:'#666' }}>This is a demo. Do not use in production without following README security notes.</p>

    {!token ? (
      <div style={{ border:'1px solid #ddd', padding:12, borderRadius:8 }}>
        <h3>Register / Login</h3>
        <input placeholder="email" value={email} onChange={e=>setEmail(e.target.value)} /><br/>
        <input placeholder="password" type="password" value={password} onChange={e=>setPassword(e.target.value)} /><br/>
        <button onClick={register}>Register</button>
        <button onClick={login}>Login</button>
      </div>
    ) : (
      <div style={{ border:'1px solid #ddd', padding:12, borderRadius:8 }}>
        <h3>Make Payment</h3>
        <input placeholder="amount" value={amount} onChange={e=>setAmount(e.target.value)} /><br/>
        <input placeholder="card number" value={card} onChange={e=>setCard(e.target.value)} /><br/>
        <button onClick={pay}>Pay</button>
        <button onClick={loadTxs}>Load Transactions</button>
        <button onClick={()=>{ localStorage.removeItem('mp_token'); setToken(''); setTxs([]); }}>Logout</button>
        <div style={{ marginTop:10 }}>{message}</div>
        <ul>
          {txs.map(t=> <li key={t.id}>#{t.id} - ${t.amount} - {t.status} - flagged:{String(t.flagged)}</li>)}
        </ul>
      </div>
    )}

    <hr/>
    <h4>Developer notes</h4>
    <pre style={{ background:'#f6f6f6', padding:10, borderRadius:6 }}>
{`API base: ${API}`}
    </pre>
  </div>)
}
