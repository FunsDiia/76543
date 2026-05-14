/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, {useState, useEffect} from 'react';
import {MapPin, Clock, Menu, Heart} from 'lucide-react';

export default function App() {
  const [time, setTime] = useState(new Date().toLocaleTimeString('uk-UA', {hour12: false}));

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toLocaleTimeString('uk-UA', {hour12: false}));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="min-h-screen bg-[var(--bg)] text-[var(--text-primary)] font-sans">
      <header className="flex items-center justify-between p-4 border-b border-[var(--border)]">
        <button className="p-2">
          <Menu className="w-6 h-6" />
        </button>
        <div className="flex items-center gap-2 bg-[var(--surface)] px-3 py-1 rounded-full">
          <span className="text-[var(--accent-gold)]">▲</span>
          <span className="font-mono text-sm">276 БПЛА</span>
        </div>
        <button className="p-2">
            <MapPin className="w-5 h-5" />
        </button>
      </header>
      
      <main className="p-4">
        <div className="h-[400px] bg-[var(--surface)] rounded-xl flex items-center justify-center border border-[var(--border)]">
            <span className="text-[var(--text-muted)]">Мапа завантажується...</span>
        </div>
      </main>

      <footer className="fixed bottom-4 left-4 right-4 text-center">
        <div className="bg-[var(--surface)] p-3 rounded-xl border border-[var(--border)]">
            <span className="text-xl font-mono" id="live-time">{time}</span>
        </div>
        <button className="w-full mt-4 bg-gradient-to-r from-[var(--accent-red)] to-red-800 text-white py-3 rounded-xl font-medium">
            ♥ ПІДТРИМАТИ ПРОЕКТ
        </button>
      </footer>
    </div>
  );
}

