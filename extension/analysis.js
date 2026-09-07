/**
 * TraceShield — Local Threat Analysis Engine
 * Pure JavaScript implementation — runs entirely in the browser extension.
 * Replaces backend /analyze endpoint with client-side heuristics.
 */

const TraceShieldAnalysis = (() => {
  'use strict';

  // ─── Brand Spoofing Database ─────────────────────────────────────────
  // Top spoofed brands with their legitimate domains
  const BRAND_DB = [
    // Indian Banks
    { name: 'sbi', domains: ['sbi.co.in', 'onlinesbi.com', 'onlinesbi.sbi'] },
    { name: 'hdfc', domains: ['hdfcbank.com', 'hdfcbank.net'] },
    { name: 'icici', domains: ['icicibank.com', 'iciciprulife.com'] },
    { name: 'axis', domains: ['axisbank.com', 'axisbank.co.in'] },
    { name: 'kotak', domains: ['kotak.com', 'kotakbank.com'] },
    { name: 'pnb', domains: ['pnbindia.in', 'pnbindia.com'] },
    { name: 'bob', domains: ['bankofbaroda.in', 'bankofbaroda.com'] },
    { name: 'canara', domains: ['canarabank.com', 'canarabank.in'] },
    { name: 'union bank', domains: ['unionbankofindia.co.in'] },
    { name: 'indian bank', domains: ['indianbank.in'] },
    // Indian Digital/Gov
    { name: 'paytm', domains: ['paytm.com'] },
    { name: 'phonepe', domains: ['phonepe.com'] },
    { name: 'gpay', domains: ['pay.google.com'] },
    { name: 'aadhaar', domains: ['uidai.gov.in'] },
    { name: 'pan card', domains: ['incometax.gov.in'] },
    { name: 'irctc', domains: ['irctc.co.in'] },
    { name: 'epfo', domains: ['epfindia.gov.in'] },
    // Global Tech
    { name: 'google', domains: ['google.com', 'gmail.com', 'accounts.google.com'] },
    { name: 'microsoft', domains: ['microsoft.com', 'outlook.com', 'live.com', 'office.com'] },
    { name: 'apple', domains: ['apple.com', 'icloud.com'] },
    { name: 'amazon', domains: ['amazon.com', 'amazon.in', 'amazon.co.uk'] },
    { name: 'meta', domains: ['facebook.com', 'meta.com', 'instagram.com'] },
    { name: 'facebook', domains: ['facebook.com', 'fb.com'] },
    { name: 'instagram', domains: ['instagram.com'] },
    { name: 'whatsapp', domains: ['whatsapp.com'] },
    { name: 'twitter', domains: ['twitter.com', 'x.com'] },
    { name: 'linkedin', domains: ['linkedin.com'] },
    { name: 'netflix', domains: ['netflix.com'] },
    { name: 'spotify', domains: ['spotify.com'] },
    { name: 'zoom', domains: ['zoom.us'] },
    { name: 'dropbox', domains: ['dropbox.com'] },
    // Finance Global
    { name: 'paypal', domains: ['paypal.com'] },
    { name: 'stripe', domains: ['stripe.com'] },
    { name: 'visa', domains: ['visa.com'] },
    { name: 'mastercard', domains: ['mastercard.com'] },
    { name: 'citibank', domains: ['citi.com', 'citibank.com'] },
    { name: 'chase', domains: ['chase.com'] },
    { name: 'wells fargo', domains: ['wellsfargo.com'] },
    // E-commerce
    { name: 'flipkart', domains: ['flipkart.com'] },
    { name: 'myntra', domains: ['myntra.com'] },
    { name: 'swiggy', domains: ['swiggy.com'] },
    { name: 'zomato', domains: ['zomato.com'] },
    // Shipping / Logistics
    { name: 'fedex', domains: ['fedex.com'] },
    { name: 'dhl', domains: ['dhl.com'] },
    { name: 'ups', domains: ['ups.com'] },
    { name: 'india post', domains: ['indiapost.gov.in'] },
    // Security
    { name: 'norton', domains: ['norton.com'] },
    { name: 'mcafee', domains: ['mcafee.com'] },
  ];

  // ─── URL Shortener domains ──────────────────────────────────────────
  const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd',
    'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc',
    'surl.li', 'clck.ru', 'rebrand.ly', 'bl.ink', 'short.io',
  ];

  // ─── Dangerous attachment extensions ────────────────────────────────
  const DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.msi', '.js', '.jse',
    '.vbs', '.vbe', '.wsf', '.wsh', '.ps1', '.hta', '.cpl', '.inf',
    '.reg', '.lnk', '.iso', '.img', '.dll', '.sys', '.cab',
    '.docm', '.xlsm', '.pptm',  // Office with macros
  ];

  // ─── Urgency Keywords ───────────────────────────────────────────────
  const URGENCY_KEYWORDS = [
    'immediately', 'urgent', 'urgently', 'expire', 'expires', 'expired',
    'suspend', 'suspended', 'suspension', 'deactivate', 'deactivated',
    'terminate', 'terminated', 'closing', 'closed', 'locked', 'lock',
    'unauthorized', 'unusual activity', 'security alert', 'warning',
    'action required', 'act now', 'within 24 hours', 'within 48 hours',
    'last chance', 'final notice', 'final warning', 'limited time',
    'verify now', 'confirm now', 'update now', 'click here immediately',
    'account will be', 'failure to', 'unless you', 'risk of',
  ];

  // ─── Credential Harvesting Patterns ─────────────────────────────────
  const ACTION_VERBS = [
    'verify', 'confirm', 'update', 'validate', 'enter', 'submit',
    'provide', 'reset', 'change', 'authenticate', 'login', 'log in',
    'sign in', 'signin', 're-enter', 'reenter',
  ];

  const CREDENTIAL_TARGETS = [
    'password', 'passcode', 'pin', 'otp', 'cvv', 'ssn', 'social security',
    'bank account', 'credit card', 'debit card', 'card number', 'account number',
    'routing number', 'aadhaar', 'pan number', 'pan card', 'ifsc',
    'credentials', 'identity', 'username', 'user id', 'userid',
    'security code', 'security question', 'mother\'s maiden',
    'date of birth', 'dob',
  ];

  // ─── Homoglyph character map ────────────────────────────────────────
  const HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
    'х': 'x', 'і': 'i', 'ј': 'j', 'ɡ': 'g', 'ɑ': 'a', 'ε': 'e',
    'ο': 'o', 'ν': 'v', 'τ': 't', 'κ': 'k', 'ℓ': 'l', 'ℎ': 'h',
    'ŋ': 'n', 'ɩ': 'i', 'ʀ': 'r', 'ꜱ': 's', 'ꞇ': 't',
    '0': 'o', '1': 'l', '!': 'i',
  };

  // ─── Utility: Levenshtein Distance ──────────────────────────────────
  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;

    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,
          dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + cost
        );
      }
    }
    return dp[m][n];
  }

  // ─── Utility: Extract domain from email / URL ───────────────────────
  function extractDomain(input) {
    if (!input) return '';
    // Handle email
    if (input.includes('@')) {
      return input.split('@').pop().toLowerCase().trim();
    }
    // Handle URL
    try {
      const url = new URL(input.startsWith('http') ? input : `https://${input}`);
      return url.hostname.toLowerCase();
    } catch {
      return input.toLowerCase().trim();
    }
  }

  // Extract SLD (second-level domain) e.g. "mail.google.com" → "google"
  function extractSLD(domain) {
    const parts = domain.replace(/^www\./, '').split('.');
    // For two-part TLDs like .co.in, .co.uk
    const twoPartTLDs = ['co.in', 'co.uk', 'org.in', 'net.in', 'ac.in', 'gov.in',
      'com.au', 'co.jp', 'co.kr', 'com.br', 'co.za'];
    const lastTwo = parts.slice(-2).join('.');
    if (twoPartTLDs.includes(lastTwo) && parts.length >= 3) {
      return parts[parts.length - 3];
    }
    return parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  }

  // ─── Utility: Check for non-ASCII / homoglyph characters ───────────
  function findHomoglyphs(text) {
    const found = [];
    for (const char of text) {
      if (HOMOGLYPH_MAP[char]) {
        found.push({ char, looksLike: HOMOGLYPH_MAP[char] });
      }
    }
    return found;
  }

  function hasNonASCII(text) {
    return /[^\x00-\x7F]/.test(text);
  }

  function isPunycode(domain) {
    return domain.includes('xn--');
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ANALYSIS MODULES
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Analyze sender identity — Reply-To mismatch, display name spoofing
   */
  function analyzeSenderIdentity(senderEmail, senderName, replyTo) {
    const results = {
      senderEmail: senderEmail || '',
      senderName: senderName || '',
      senderDomain: extractDomain(senderEmail),
      replyToDomain: replyTo ? extractDomain(replyTo) : '',
      replyToMismatch: false,
      displayNameSpoof: false,
      spoofedBrand: null,
      flags: [],
    };

    // Reply-To mismatch
    if (results.replyToDomain && results.senderDomain &&
        results.replyToDomain !== results.senderDomain) {
      results.replyToMismatch = true;
      results.flags.push(`Reply-To domain (${results.replyToDomain}) differs from sender (${results.senderDomain})`);
    }

    // Display name brand spoofing
    if (senderName) {
      const nameLower = senderName.toLowerCase();
      const senderSLD = extractSLD(results.senderDomain);

      for (const brand of BRAND_DB) {
        if (nameLower.includes(brand.name)) {
          const isLegit = brand.domains.some(d => {
            const brandSLD = extractSLD(d);
            return senderSLD === brandSLD || results.senderDomain.endsWith(d);
          });

          if (!isLegit) {
            results.displayNameSpoof = true;
            results.spoofedBrand = brand.name.toUpperCase();
            results.flags.push(
              `Display name contains "${brand.name}" but domain "${results.senderDomain}" doesn't match legitimate domains`
            );
            break;
          }
        }
      }
    }

    return results;
  }

  /**
   * Analyze domains for lookalikes and homoglyphs
   */
  function analyzeDomains(senderDomain, bodyLinks) {
    const results = {
      lookalikeDomainsFound: [],
      homoglyphDomainsFound: [],
      punycodeDetected: false,
      flags: [],
    };

    const domainsToCheck = new Set();
    if (senderDomain) domainsToCheck.add(senderDomain);

    // Collect link domains from body
    for (const link of (bodyLinks || [])) {
      const domain = extractDomain(link);
      if (domain) domainsToCheck.add(domain);
    }

    for (const domain of domainsToCheck) {
      // Punycode check
      if (isPunycode(domain)) {
        results.punycodeDetected = true;
        results.homoglyphDomainsFound.push({
          domain,
          type: 'punycode',
          suspicious: true,
        });
        results.flags.push(`Punycode (internationalized) domain detected: ${domain}`);
        continue;
      }

      // Homoglyph character check
      const homoglyphs = findHomoglyphs(domain);
      if (homoglyphs.length > 0) {
        results.homoglyphDomainsFound.push({
          domain,
          type: 'homoglyph',
          chars: homoglyphs,
          suspicious: true,
        });
        results.flags.push(
          `Homoglyph characters found in "${domain}": ${homoglyphs.map(h => `'${h.char}' looks like '${h.looksLike}'`).join(', ')}`
        );
        continue;
      }

      // Non-ASCII check
      if (hasNonASCII(domain)) {
        results.homoglyphDomainsFound.push({
          domain,
          type: 'non-ascii',
          suspicious: true,
        });
        results.flags.push(`Non-ASCII characters in domain: ${domain}`);
        continue;
      }

      // Lookalike (Levenshtein) check against brands
      const domainSLD = extractSLD(domain);
      for (const brand of BRAND_DB) {
        for (const legit of brand.domains) {
          const legitSLD = extractSLD(legit);
          if (domainSLD === legitSLD) continue; // Exact match = legit

          const dist = levenshtein(domainSLD, legitSLD);
          // Flag if very close but not exact (edit distance 1-2)
          if (dist > 0 && dist <= 2 && domainSLD.length >= 3) {
            results.lookalikeDomainsFound.push({
              suspicious: domain,
              looksLike: legit,
              brand: brand.name,
              editDistance: dist,
            });
            results.flags.push(
              `"${domain}" is ${dist} edit(s) from "${legit}" (${brand.name.toUpperCase()}) — possible lookalike`
            );
          }
        }
      }
    }

    // Deduplicate lookalike flags
    const seen = new Set();
    results.lookalikeDomainsFound = results.lookalikeDomainsFound.filter(item => {
      const key = `${item.suspicious}:${item.looksLike}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return results;
  }

  /**
   * Analyze URLs in email body
   */
  function analyzeUrls(bodyHtml, bodyText) {
    const results = {
      totalLinks: 0,
      urlShortenersFound: [],
      displayHrefMismatches: [],
      suspiciousLinks: [],
      flags: [],
    };

    if (!bodyHtml) return results;

    // Parse links from HTML
    const parser = new DOMParser();
    const doc = parser.parseFromString(bodyHtml, 'text/html');
    const anchors = doc.querySelectorAll('a[href]');

    results.totalLinks = anchors.length;

    for (const a of anchors) {
      const href = (a.getAttribute('href') || '').trim();
      const displayText = (a.textContent || '').trim();

      if (!href || href.startsWith('mailto:') || href.startsWith('#')) continue;

      const hrefDomain = extractDomain(href);

      // URL shortener check
      if (URL_SHORTENERS.some(s => hrefDomain === s || hrefDomain.endsWith('.' + s))) {
        results.urlShortenersFound.push({ url: href, shortener: hrefDomain });
        results.flags.push(`URL shortener detected: ${hrefDomain} (hides real destination)`);
      }

      // Display text vs href mismatch (link says "google.com" but goes elsewhere)
      const displayLooksLikeDomain = /^(https?:\/\/)?[a-z0-9][a-z0-9.-]+\.[a-z]{2,}/i.test(displayText);
      if (displayLooksLikeDomain) {
        const displayDomain = extractDomain(displayText);
        if (displayDomain && hrefDomain && displayDomain !== hrefDomain) {
          results.displayHrefMismatches.push({
            displayText,
            displayDomain,
            actualHref: href,
            actualDomain: hrefDomain,
          });
          results.flags.push(
            `Link text shows "${displayDomain}" but actually goes to "${hrefDomain}" — deceptive link`
          );
        }
      }
    }

    return results;
  }

  /**
   * Analyze email language for urgency and credential harvesting
   */
  function analyzeLanguage(subject, bodyText) {
    const results = {
      urgencyScore: 0,
      urgencyKeywordsHit: [],
      credentialHarvestingDetected: false,
      credentialPhrases: [],
      allCapsSubject: false,
      flags: [],
    };

    const fullText = `${subject || ''} ${bodyText || ''}`.toLowerCase();

    // Urgency keyword scoring
    let urgencyHits = 0;
    for (const keyword of URGENCY_KEYWORDS) {
      if (fullText.includes(keyword)) {
        urgencyHits++;
        results.urgencyKeywordsHit.push(keyword);
      }
    }
    // Normalize: 0 hits = 0.0, 5+ hits = 1.0
    results.urgencyScore = Math.min(1.0, urgencyHits / 5);

    // All-caps subject
    if (subject && subject === subject.toUpperCase() && subject.length > 5) {
      results.allCapsSubject = true;
      results.urgencyScore = Math.min(1.0, results.urgencyScore + 0.15);
      results.flags.push('Subject line is ALL CAPS — urgency manipulation');
    }

    if (results.urgencyKeywordsHit.length > 0) {
      results.flags.push(
        `Urgency language detected (${results.urgencyKeywordsHit.length} triggers): ${results.urgencyKeywordsHit.slice(0, 4).join(', ')}`
      );
    }

    // Credential harvesting — look for action verb + credential target within proximity
    for (const verb of ACTION_VERBS) {
      const verbIdx = fullText.indexOf(verb);
      if (verbIdx === -1) continue;

      const window = fullText.substring(
        Math.max(0, verbIdx - 40),
        Math.min(fullText.length, verbIdx + verb.length + 80)
      );

      for (const target of CREDENTIAL_TARGETS) {
        if (window.includes(target)) {
          results.credentialHarvestingDetected = true;
          results.credentialPhrases.push(`"${verb}" + "${target}"`);
        }
      }
    }

    if (results.credentialHarvestingDetected) {
      results.flags.push(
        `Credential harvesting language: ${results.credentialPhrases.slice(0, 3).join(', ')}`
      );
    }

    return results;
  }

  /**
   * Analyze attachments from Gmail DOM
   */
  function analyzeAttachments(attachmentNames) {
    const results = {
      totalAttachments: attachmentNames.length,
      dangerousAttachments: [],
      flags: [],
    };

    for (const name of attachmentNames) {
      const lower = name.toLowerCase();
      for (const ext of DANGEROUS_EXTENSIONS) {
        if (lower.endsWith(ext)) {
          results.dangerousAttachments.push({ filename: name, extension: ext });
          results.flags.push(`Dangerous attachment: "${name}" (${ext} — potential malware vector)`);
          break;
        }
      }
    }

    return results;
  }

  /**
   * Calculate composite risk score from all analysis modules
   */
  function calculateRiskScore(sender, domains, urls, language, attachments) {
    let headerScore = 0;   // Max 40
    let contentScore = 0;  // Max 45
    const triggeredReasons = [];
    const verifiedAuths = [];

    // ── Header / Sender (Max 40) ────────────────────────────
    if (sender.replyToMismatch) {
      headerScore += 15;
      triggeredReasons.push('Reply-To domain mismatch detected');
    } else {
      verifiedAuths.push('Reply-To: Consistent with sender domain');
    }

    if (sender.displayNameSpoof) {
      headerScore += 15;
      triggeredReasons.push(`Display name spoofing: impersonates ${sender.spoofedBrand}`);
    } else {
      verifiedAuths.push('Display Name: No brand impersonation detected');
    }

    if (attachments.dangerousAttachments.length > 0) {
      headerScore += 20;
      triggeredReasons.push(`${attachments.dangerousAttachments.length} dangerous attachment(s) identified`);
    } else if (attachments.totalAttachments > 0) {
      verifiedAuths.push('Attachments: No high-risk executable types found');
    }

    headerScore = Math.min(40, headerScore);

    // ── Content Threats (Max 45) ────────────────────────────
    if (language.urgencyScore > 0.4) {
      const urgencyPoints = Math.round(language.urgencyScore * 15);
      contentScore += urgencyPoints;
      triggeredReasons.push(`Urgency manipulation score: ${Math.round(language.urgencyScore * 100)}%`);
    } else {
      verifiedAuths.push('Language: No urgency manipulation detected');
    }

    if (language.credentialHarvestingDetected) {
      contentScore += 15;
      triggeredReasons.push('Credential harvesting language detected');
    }

    if (domains.lookalikeDomainsFound.length > 0) {
      contentScore += 20;
      const first = domains.lookalikeDomainsFound[0];
      triggeredReasons.push(`Lookalike domain: "${first.suspicious}" mimics ${first.brand}`);
    }

    if (domains.homoglyphDomainsFound.some(h => h.suspicious)) {
      contentScore += 20;
      triggeredReasons.push('Homoglyph/Punycode domain spoofing detected');
    }

    if (urls.urlShortenersFound.length > 0) {
      contentScore += 5;
      triggeredReasons.push(`URL shortener(s) hiding destination: ${urls.urlShortenersFound[0].shortener}`);
    }

    if (urls.displayHrefMismatches.length > 0) {
      contentScore += 15;
      const first = urls.displayHrefMismatches[0];
      triggeredReasons.push(`Deceptive link: displays "${first.displayDomain}" but links to "${first.actualDomain}"`);
    }

    if (domains.lookalikeDomainsFound.length === 0 && domains.homoglyphDomainsFound.length === 0) {
      verifiedAuths.push('Domains: No lookalike or homoglyph domains found');
    }

    contentScore = Math.min(45, contentScore);

    // ── Total Score ─────────────────────────────────────────
    let totalScore = headerScore + contentScore;
    totalScore = Math.min(100, totalScore);

    // Mitigating discount: if no hard threats, cap at 20
    const hasHardThreats = sender.displayNameSpoof ||
      sender.replyToMismatch ||
      domains.lookalikeDomainsFound.length > 0 ||
      domains.homoglyphDomainsFound.length > 0 ||
      attachments.dangerousAttachments.length > 0 ||
      urls.displayHrefMismatches.length > 0 ||
      language.credentialHarvestingDetected;

    if (!hasHardThreats && totalScore > 20) {
      totalScore = Math.min(20, totalScore);
    }

    // Determine tier
    let riskTier, confidenceLevel, confidenceReason;
    if (totalScore >= 61) {
      riskTier = 'High';
      confidenceLevel = 'High Confidence';
      confidenceReason = 'Multiple objective threat signals confirmed';
    } else if (totalScore >= 31) {
      riskTier = 'Medium';
      confidenceLevel = 'Moderate Confidence';
      confidenceReason = 'Suspicious patterns detected — exercise caution';
    } else {
      riskTier = 'Low';
      confidenceLevel = 'Low Risk';
      confidenceReason = 'No malicious patterns detected in visible content';
    }

    // Recommendations
    const recommendations = [];
    if (totalScore >= 61) {
      recommendations.push('Do NOT click any links in this email');
      recommendations.push('Report this email as phishing to your email provider');
      if (attachments.dangerousAttachments.length > 0) {
        recommendations.push('Do NOT download or open any attachments');
      }
    } else if (totalScore >= 31) {
      recommendations.push('Verify the sender through an independent channel');
      recommendations.push('Hover over links to check destinations before clicking');
    }

    return {
      finalRiskScore: totalScore,
      riskTier,
      confidenceLevel,
      confidenceReason,
      scoreBreakdown: {
        headerAuthentication: { points: headerScore, maxScore: 40 },
        contentThreats: { points: contentScore, maxScore: 45 },
      },
      triggeredReasons,
      verifiedAuthentications: verifiedAuths,
      recommendations,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // MAIN ANALYSIS FUNCTION
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Run full threat analysis on extracted email data.
   *
   * @param {Object} emailData
   * @param {string} emailData.senderEmail
   * @param {string} emailData.senderName
   * @param {string} emailData.subject
   * @param {string} emailData.bodyText
   * @param {string} emailData.bodyHtml
   * @param {string[]} emailData.attachmentNames
   * @param {string} [emailData.replyTo]
   * @returns {Object} Full analysis record
   */
  function analyze(emailData) {
    const {
      senderEmail = '',
      senderName = '',
      subject = '',
      bodyText = '',
      bodyHtml = '',
      attachmentNames = [],
      replyTo = '',
    } = emailData;

    // Extract body links for domain analysis
    const bodyLinks = [];
    if (bodyHtml) {
      try {
        const parser = new DOMParser();
        const doc = parser.parseFromString(bodyHtml, 'text/html');
        doc.querySelectorAll('a[href]').forEach(a => {
          const href = a.getAttribute('href');
          if (href && !href.startsWith('mailto:') && !href.startsWith('#')) {
            bodyLinks.push(href);
          }
        });
      } catch { /* silent */ }
    }

    // Run analysis modules
    const senderAnalysis = analyzeSenderIdentity(senderEmail, senderName, replyTo);
    const domainAnalysis = analyzeDomains(senderAnalysis.senderDomain, bodyLinks);
    const urlAnalysis = analyzeUrls(bodyHtml, bodyText);
    const languageAnalysis = analyzeLanguage(subject, bodyText);
    const attachmentAnalysis = analyzeAttachments(attachmentNames);

    // Calculate score
    const scoring = calculateRiskScore(
      senderAnalysis, domainAnalysis, urlAnalysis, languageAnalysis, attachmentAnalysis
    );

    // Build unified record
    const record = {
      analyzedAt: new Date().toISOString(),
      analysisMode: 'Extension-Local',
      senderIdentity: senderAnalysis,
      domainAnalysis: domainAnalysis,
      urlAnalysis: urlAnalysis,
      languageAnalysis: languageAnalysis,
      attachmentAnalysis: attachmentAnalysis,
      scoring: {
        final_risk_score: scoring.finalRiskScore,
        risk_tier: scoring.riskTier,
        confidence_level: scoring.confidenceLevel,
        confidence_reason: scoring.confidenceReason,
        score_breakdown: scoring.scoreBreakdown,
        triggered_reasons: scoring.triggeredReasons,
        verified_authentications: scoring.verifiedAuthentications,
        recommendations: scoring.recommendations,
      },
      // Collect all flags across modules
      allFlags: [
        ...senderAnalysis.flags,
        ...domainAnalysis.flags,
        ...urlAnalysis.flags,
        ...languageAnalysis.flags,
        ...attachmentAnalysis.flags,
      ],
    };

    return record;
  }

  // Public API
  return { analyze, levenshtein, extractDomain, extractSLD, BRAND_DB };
})();
