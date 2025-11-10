const express = require('express');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    ok: true, 
    time: new Date().toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh' }),
    region: 'VN'
  });
});

// 34 MATHEMATICAL EQUATIONS
const math = {
  fib: (n) => n <= 1 ? n : math.fib(n-1) + math.fib(n-2),
  isPrime: (n) => { if (n < 2) return false; for (let i = 2; i*i <= n; i++) if (n % i === 0) return false; return true; },
  matmul: (a, b) => a.map(row => row.map((_, i) => row.reduce((sum, val, j) => sum + val * b[j][i], 0))),
  fact: (n) => n <= 1 ? 1 : n * math.fact(n-1),
  gcd: (a, b) => b === 0 ? a : math.gcd(b, a % b),
  binom: (n, k) => math.fact(n) / (math.fact(k) * math.fact(n-k)),
  det2: (m) => m[0][0]*m[1][1] - m[0][1]*m[1][0],
  totient: (n) => { let r = 0; for (let i = 1; i <= n; i++) if (math.gcd(n, i) === 1) r++; return r; },
  quad: (a, b, c) => { const d = b*b - 4*a*c; return d < 0 ? [] : [(-b + Math.sqrt(d))/(2*a), (-b - Math.sqrt(d))/(2*a)]; },
  modinv: (a, m) => { for (let x = 1; x < m; x++) if ((a * x) % m === 1) return x; return null; },
  powmod: (b, e, m) => { let r = 1; while (e) { if (e & 1) r = (r * b) % m; b = (b * b) % m; e >>= 1; } return r; },
  collatz: (n) => { const seq = [n]; while (n > 1) { n = n % 2 === 0 ? n / 2 : 3*n + 1; seq.push(n); } return seq; },
  ack: (m, n) => m === 0 ? n + 1 : n === 0 ? math.ack(m - 1, 1) : math.ack(m - 1, math.ack(m, n - 1)),
  catalan: (n) => math.binom(2*n, n) / (n + 1),
  stirling: (n, k) => k === 0 || k === n ? 1 : k * math.stirling(n-1, k) + math.stirling(n-1, k-1),
  legendre: (n) => { let s = 0; for (let i = 1; i <= n; i++) s += Math.floor(n/i); return s; },
  bell: (n) => { let b = [1]; for (let i = 1; i <= n; i++) { let t = [b[i-1]]; for (let j = 1; j < i; j++) t.push(b[j-1] + t[j-1]); t.push(1); b = t; } return b[n]; },
  harmonic: (n) => { let h = 0; for (let i = 1; i <= n; i++) h += 1/i; return h; },
  geometric: (r, n) => (1 - Math.pow(r, n+1)) / (1 - r),
  lucas: (n) => n === 0 ? 2 : n === 1 ? 1 : math.lucas(n-1) + math.lucas(n-2),
  pell: (n) => n <= 1 ? n : 2*math.pell(n-1) + math.pell(n-2),
  mersenne: (p) => (1 << p) - 1,
  isHappy: (n) => { const seen = new Set(); while (n !== 1 && !seen.has(n)) { seen.add(n); n = n.toString().split('').reduce((s, d) => s + d*d, 0); } return n === 1; },
  tribonacci: (n) => n <= 2 ? n : math.tribonacci(n-1) + math.tribonacci(n-2) + math.tribonacci(n-3),
  padovan: (n) => n <= 2 ? 1 : math.padovan(n-2) + math.padovan(n-3),
  motzkin: (n) => n <= 1 ? 1 : math.motzkin(n-1) + (n >= 2 ? (n-2)*math.motzkin(n-2) + (n-1)*math.motzkin(n-3) : 0) / n,
  delannoy: (m, n) => { let d = Array(m+1).fill().map(() => Array(n+1).fill(0)); for (let i = 0; i <= m; i++) for (let j = 0; j <= n; j++) d[i][j] = (i ? d[i-1][j] : 0) + (j ? d[i][j-1] : 0) + (i && j ? d[i-1][j-1] : 0); return d[m][n]; },
  jacobsthal: (n) => n === 0 ? 0 : n === 1 ? 1 : math.jacobsthal(n-1) + 2*math.jacobsthal(n-2),
  sylvester: (n) => n <= 1 ? n+1 : math.sylvester(n-1) * (math.sylvester(n-1) + 1),
  eulerZigzag: (n) => { let e = [1]; for (let i = 1; i <= n; i++) e[i] = (i % 2 === 0 ? 1 : -1) * math.binom(2*i, i) / (i + 1); return e[n]; },
  narayana: (n, k) => math.binom(n, k) * math.binom(n, k-1) / n,
  schroeder: (n) => { let s = [1, 2]; for (let i = 2; i <= n; i++) s[i] = 6*i*s[i-1] / (i+1) - (i-3)*s[i-2] / (i+1); return s[n]; },
  fermat: (n) => Math.pow(2, Math.pow(2, n)) + 1
};

// API endpoint
app.get('/math', async (req, res) => {
  const { func, ...params } = req.query;
  if (!func || !math[func]) return res.status(400).json({ error: "Invalid function" });

  try {
    const result = math[func](...Object.values(params).map(Number));
    res.json({ func, params, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} (Vietnam Time)`);
});
