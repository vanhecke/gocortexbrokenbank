// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
'use client';

import { useState, useEffect, useCallback } from 'react';
import { ping } from './actions';

const ACCOUNTS = {
  '1234': {
    holder: 'J. Smith',
    account: '0012-3456',
    balance: 2847.50,
    transactions: [
      { date: '2025-02-15', desc: 'Coles Supermarket', amount: -89.75 },
      { date: '2025-02-14', desc: 'PTV Myki Top-Up', amount: -40.00 },
      { date: '2025-02-13', desc: 'Netflix Subscription', amount: -16.99 },
      { date: '2025-02-12', desc: 'Bunnings Warehouse', amount: -67.40 },
      { date: '2025-02-11', desc: 'Salary Deposit', amount: 2450.00 },
      { date: '2025-02-10', desc: 'Woolworths', amount: -112.30 },
    ],
  },
  '0000': {
    holder: 'S. Chen',
    account: '0098-7654',
    balance: 156230.00,
    transactions: [
      { date: '2025-02-15', desc: 'Crown Casino Melbourne', amount: -12500.00 },
      { date: '2025-02-14', desc: 'Property Settlement', amount: -285000.00 },
      { date: '2025-02-13', desc: 'Executive Salary', amount: 125000.00 },
      { date: '2025-02-12', desc: 'Investment Returns', amount: 45000.00 },
      { date: '2025-02-11', desc: 'Brighton Yacht Club', amount: -18500.00 },
    ],
  },
  '1111': {
    holder: 'M. Williams',
    account: '0045-6789',
    balance: 489.15,
    transactions: [
      { date: '2025-02-15', desc: '7-Eleven Melbourne CBD', amount: -12.50 },
      { date: '2025-02-14', desc: 'Uber Eats', amount: -34.80 },
      { date: '2025-02-13', desc: 'Maccas Drive-Thru', amount: -18.95 },
      { date: '2025-02-12', desc: 'Salary Deposit', amount: 1850.00 },
      { date: '2025-02-11', desc: 'Dan Murphy\'s', amount: -54.90 },
    ],
  },
};

const SERVICE_PIN = '7777';
const QUICK_AMOUNTS = [20, 50, 100, 200, 500];

function formatCurrency(amount) {
  return '$' + Math.abs(amount).toLocaleString('en-AU', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

export default function ATMPage() {
  const [screen, setScreen] = useState('pin');
  const [pin, setPin] = useState('');
  const [pinError, setPinError] = useState('');
  const [attempts, setAttempts] = useState(3);
  const [currentAccount, setCurrentAccount] = useState(null);
  const [withdrawAmount, setWithdrawAmount] = useState('');
  const [depositAmount, setDepositAmount] = useState('');
  const [message, setMessage] = useState(null);
  const [jackpotActive, setJackpotActive] = useState(false);
  const [jackpotAmount, setJackpotAmount] = useState(0);
  const [jackpotNotes, setJackpotNotes] = useState(0);
  const [floatingNotes, setFloatingNotes] = useState([]);

  const handlePinKey = useCallback((key) => {
    if (screen !== 'pin') return;
    setPinError('');
    setMessage(null);

    if (key === 'CLR') {
      setPin('');
      return;
    }

    if (key === 'ENT') {
      if (pin.length !== 4) return;
      
      if (pin === SERVICE_PIN) {
        setScreen('service');
        setPin('');
        return;
      }
      
      if (ACCOUNTS[pin]) {
        setCurrentAccount({ ...ACCOUNTS[pin], pin });
        setScreen('menu');
        setPin('');
        setAttempts(3);
        return;
      }
      
      const newAttempts = attempts - 1;
      setAttempts(newAttempts);
      setPin('');
      
      if (newAttempts <= 0) {
        setPinError('Card retained. Contact your branch.');
        setTimeout(() => {
          setAttempts(3);
          setPinError('');
        }, 3000);
      } else {
        setPinError(`Invalid PIN. ${newAttempts} attempt${newAttempts !== 1 ? 's' : ''} remaining.`);
      }
      return;
    }

    if (pin.length < 4) {
      setPin(prev => prev + key);
    }
  }, [pin, screen, attempts]);

  const handleWithdraw = (amount) => {
    if (!currentAccount) return;
    if (amount > currentAccount.balance) {
      setMessage({ type: 'error', text: 'Insufficient funds' });
      return;
    }
    setCurrentAccount(prev => ({ ...prev, balance: prev.balance - amount }));
    setMessage({ type: 'success', text: `Dispensing $${amount.toFixed(2)}... Please collect your cash.` });
    setTimeout(() => {
      setMessage(null);
      setScreen('menu');
    }, 2500);
  };

  const handleDeposit = () => {
    const amount = parseFloat(depositAmount);
    if (!amount || amount <= 0) {
      setMessage({ type: 'error', text: 'Enter a valid amount' });
      return;
    }
    setCurrentAccount(prev => ({ ...prev, balance: prev.balance + amount }));
    setMessage({ type: 'success', text: `Deposit of $${amount.toFixed(2)} successful.` });
    setDepositAmount('');
    setTimeout(() => {
      setMessage(null);
      setScreen('menu');
    }, 2500);
  };

  const exitToPin = () => {
    setScreen('pin');
    setCurrentAccount(null);
    setPin('');
    setMessage(null);
    setWithdrawAmount('');
    setDepositAmount('');
  };

  const startJackpot = () => {
    setJackpotActive(true);
    setJackpotAmount(0);
    setJackpotNotes(0);
    setFloatingNotes([]);
  };

  useEffect(() => {
    ping().catch(() => {});
  }, []);

  useEffect(() => {
    if (!jackpotActive) return;
    
    const counterInterval = setInterval(() => {
      setJackpotAmount(prev => {
        const increment = Math.floor(Math.random() * 500) + 100;
        return prev + increment;
      });
      setJackpotNotes(prev => prev + Math.floor(Math.random() * 3) + 1);
    }, 80);

    const noteInterval = setInterval(() => {
      setFloatingNotes(prev => {
        const newNote = {
          id: Date.now() + Math.random(),
          left: Math.random() * 90 + 5,
          duration: Math.random() * 2 + 1.5,
          delay: Math.random() * 0.5,
          denomination: [5, 10, 20, 50, 100][Math.floor(Math.random() * 5)],
        };
        const filtered = prev.length > 20 ? prev.slice(-15) : prev;
        return [...filtered, newNote];
      });
    }, 200);

    return () => {
      clearInterval(counterInterval);
      clearInterval(noteInterval);
    };
  }, [jackpotActive]);

  const stopJackpot = () => {
    setJackpotActive(false);
    setFloatingNotes([]);
    setMessage({ type: 'warning', text: 'Dispense test complete. Audit log suspended.' });
  };

  const renderPinScreen = () => (
    <div className="fade-in" style={{ textAlign: 'center' }}>
      <div className="screen-title">Enter Your PIN</div>
      <div className="screen-subtitle">Mars Banking Initiative</div>
      <div className="pin-display">
        {[0, 1, 2, 3].map(i => (
          <div key={i} className={`pin-dot ${i < pin.length ? 'filled' : ''}`} />
        ))}
      </div>
      {pinError && <div className="message-box error">{pinError}</div>}
      <div className="keypad">
        {['1','2','3','4','5','6','7','8','9','CLR','0','ENT'].map(key => (
          <button
            key={key}
            className={`key-btn ${key === 'CLR' ? 'clear' : key === 'ENT' ? 'enter' : ''}`}
            onClick={() => handlePinKey(key)}
          >
            {key}
          </button>
        ))}
      </div>
    </div>
  );

  const renderMenu = () => (
    <div className="fade-in" style={{ textAlign: 'center' }}>
      <div className="screen-title">Main Menu</div>
      <div className="screen-subtitle">Welcome, {currentAccount?.holder}</div>
      <button className="menu-btn" onClick={() => setScreen('balance')}>Balance Enquiry</button>
      <button className="menu-btn" onClick={() => { setScreen('withdraw'); setMessage(null); }}>Withdrawal</button>
      <button className="menu-btn" onClick={() => { setScreen('deposit'); setMessage(null); }}>Deposit</button>
      <button className="menu-btn" onClick={() => setScreen('history')}>Transaction History</button>
      <button className="menu-btn danger" onClick={exitToPin}>Remove Card</button>
    </div>
  );

  const renderBalance = () => (
    <div className="fade-in" style={{ textAlign: 'center' }}>
      <div className="screen-title">Balance Enquiry</div>
      <div className="info-row">
        <span className="info-label">Account Holder</span>
        <span className="info-value">{currentAccount?.holder}</span>
      </div>
      <div className="info-row">
        <span className="info-label">Account</span>
        <span className="info-value">{currentAccount?.account}</span>
      </div>
      <div className="balance-display">{formatCurrency(currentAccount?.balance || 0)}</div>
      <div style={{ fontSize: '10px', color: 'var(--atm-text-dim)', marginBottom: '16px' }}>Available Balance (AUD)</div>
      <button className="menu-btn" onClick={() => setScreen('menu')}>Back to Menu</button>
    </div>
  );

  const renderWithdraw = () => (
    <div className="fade-in" style={{ textAlign: 'center' }}>
      <div className="screen-title">Cash Withdrawal</div>
      <div className="screen-subtitle">Available: {formatCurrency(currentAccount?.balance || 0)}</div>
      {message && <div className={`message-box ${message.type}`}>{message.text}</div>}
      <div className="amount-grid">
        {QUICK_AMOUNTS.map(amt => (
          <button key={amt} className="amount-btn" onClick={() => handleWithdraw(amt)}>
            ${amt}
          </button>
        ))}
        <button className="amount-btn" onClick={() => {
          const custom = prompt('Enter amount:');
          if (custom) handleWithdraw(parseFloat(custom));
        }}>
          Other
        </button>
      </div>
      <button className="menu-btn" onClick={() => { setScreen('menu'); setMessage(null); }}>Back to Menu</button>
    </div>
  );

  const renderDeposit = () => (
    <div className="fade-in" style={{ textAlign: 'center' }}>
      <div className="screen-title">Cash Deposit</div>
      {message && <div className={`message-box ${message.type}`}>{message.text}</div>}
      <input
        className="input-field"
        type="number"
        placeholder="Enter amount"
        value={depositAmount}
        onChange={(e) => setDepositAmount(e.target.value)}
        style={{ margin: '16px 0' }}
      />
      <button className="menu-btn" onClick={handleDeposit}>Confirm Deposit</button>
      <button className="menu-btn" onClick={() => { setScreen('menu'); setMessage(null); }}>Back to Menu</button>
    </div>
  );

  const renderHistory = () => (
    <div className="fade-in" style={{ textAlign: 'center' }}>
      <div className="screen-title">Recent Transactions</div>
      <div className="tx-table">
        {(currentAccount?.transactions || []).map((tx, i) => (
          <div key={i} className="tx-row">
            <span style={{ color: 'var(--atm-text-dim)', width: '80px', fontSize: '10px' }}>{tx.date}</span>
            <span className="tx-desc">{tx.desc}</span>
            <span className={`tx-amount ${tx.amount < 0 ? 'debit' : 'credit'}`}>
              {tx.amount < 0 ? '-' : '+'}${Math.abs(tx.amount).toFixed(2)}
            </span>
          </div>
        ))}
      </div>
      <button className="menu-btn" onClick={() => setScreen('menu')} style={{ marginTop: '16px' }}>Back to Menu</button>
    </div>
  );

  const renderServiceMenu = () => (
    <div className="fade-in">
      <div className="service-panel">
        <div className="service-header">
          <div className="service-title">SERVICE MENU</div>
          <div className="service-subtitle">Authorised Personnel Only</div>
        </div>
        {message && <div className={`message-box ${message.type}`}>{message.text}</div>}
        <button className="menu-btn service" onClick={() => setScreen('diagnostics')}>Hardware Diagnostics</button>
        <button className="menu-btn service" onClick={() => setScreen('cassette')}>Cash Cassette Status</button>
        <button className="menu-btn danger" onClick={startJackpot}>Dispense Test</button>
        <button className="menu-btn service" onClick={() => setMessage({ type: 'success', text: 'Network: 192.168.1.1 | Latency: 12ms | Status: Connected' })}>Network Diagnostics</button>
        <button className="menu-btn" onClick={() => { exitToPin(); }}>Exit Service Mode</button>
      </div>
    </div>
  );

  const renderDiagnostics = () => {
    const components = [
      { name: 'Card Reader', status: 'ok' },
      { name: 'Cash Dispenser', status: 'ok' },
      { name: 'Receipt Printer', status: 'warning' },
      { name: 'Network Adapter', status: 'ok' },
      { name: 'Encryption Module', status: 'ok' },
    ];
    const statusLabels = { ok: 'OPERATIONAL', warning: 'WARNING', error: 'FAULT' };
    
    return (
      <div className="fade-in">
        <div className="service-panel">
          <div className="service-header">
            <div className="service-title">HARDWARE DIAGNOSTICS</div>
          </div>
          {components.map((c, i) => (
            <div key={i} className="diag-row">
              <span className="diag-label">{c.name}</span>
              <span className={`diag-status ${c.status}`}>{statusLabels[c.status]}</span>
            </div>
          ))}
          <button className="menu-btn service" onClick={() => setScreen('service')} style={{ marginTop: '16px' }}>Back to Service Menu</button>
        </div>
      </div>
    );
  };

  const renderCassette = () => {
    const cassettes = [
      { label: 'Cassette A ($50 notes)', remaining: 487, capacity: 500, pct: 97 },
      { label: 'Cassette B ($20 notes)', remaining: 312, capacity: 500, pct: 62 },
      { label: 'Cassette C ($100 notes)', remaining: 98, capacity: 300, pct: 33 },
      { label: 'Cassette D ($10 notes)', remaining: 445, capacity: 500, pct: 89 },
    ];
    
    return (
      <div className="fade-in">
        <div className="service-panel">
          <div className="service-header">
            <div className="service-title">CASH CASSETTE STATUS</div>
          </div>
          {cassettes.map((c, i) => (
            <div key={i} style={{ padding: '10px 0' }}>
              <div className="cassette-row" style={{ borderBottom: 'none', padding: '4px 12px' }}>
                <span className="cassette-label">{c.label}</span>
                <span className="cassette-info">{c.remaining} / {c.capacity}</span>
              </div>
              <div style={{ padding: '0 12px' }}>
                <div className="cassette-bar">
                  <div
                    className={`cassette-fill ${c.pct > 60 ? 'high' : c.pct > 30 ? 'medium' : 'low'}`}
                    style={{ width: `${c.pct}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
          <button className="menu-btn service" onClick={() => setScreen('service')} style={{ marginTop: '16px' }}>Back to Service Menu</button>
        </div>
      </div>
    );
  };

  const renderJackpot = () => (
    <div className="jackpot-overlay" onClick={jackpotAmount > 50000 ? stopJackpot : undefined}>
      {floatingNotes.map(note => (
        <div
          key={note.id}
          className="floating-note"
          style={{
            left: `${note.left}%`,
            animationDuration: `${note.duration}s`,
            animationDelay: `${note.delay}s`,
          }}
        >
          ${note.denomination}
        </div>
      ))}
      <div className="jackpot-warning">HARDWARE OVERRIDE ACTIVE</div>
      <div style={{ fontSize: '22px', color: 'var(--atm-amber)', letterSpacing: '2px', marginBottom: '8px' }}>
        DISPENSE TEST INITIATED
      </div>
      <div className="jackpot-counter">{formatCurrency(jackpotAmount)}</div>
      <div className="jackpot-notes">{jackpotNotes} notes ejected</div>
      <div className="jackpot-info">
        <div className="red">All cassette locks disengaged</div>
        <div className="red">Dispenser Motor: CONTINUOUS FEED</div>
        <div className="amber">Security interlock: BYPASSED</div>
        <div className="amber">Audit log: SUSPENDED</div>
      </div>
      {jackpotAmount > 50000 && (
        <div style={{ marginTop: '16px', fontSize: '20px', color: 'var(--atm-text-dim)' }}>
          [Click to end dispense test]
        </div>
      )}
    </div>
  );

  return (
    <>
      {screen === 'pin' && renderPinScreen()}
      {screen === 'menu' && renderMenu()}
      {screen === 'balance' && renderBalance()}
      {screen === 'withdraw' && renderWithdraw()}
      {screen === 'deposit' && renderDeposit()}
      {screen === 'history' && renderHistory()}
      {screen === 'service' && renderServiceMenu()}
      {screen === 'diagnostics' && renderDiagnostics()}
      {screen === 'cassette' && renderCassette()}
      {jackpotActive && renderJackpot()}
    </>
  );
}
