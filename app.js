const THREAT_PATTERNS = {
  phishing: {
    keywords: [
      'account suspended', 'verify your account', 'login immediately', 'confirm your identity',
      'update your details', 'secure your account', 'unusual activity', 'password expired',
      'reset your password', 'click here', 'urgent action required', 'suspended', 'blocked',
      'limited', 'restore access', 'reverify', 'confirm identity', 'bank account', 'card details',
      'ssn', 'aadhaar', 'pan card', 'kyc', 'your account', 'your payment', 'suspicious activity',
      'unauthorized', 'security alert', 'verify now', 'act now to avoid', 'immediate attention',
      'otp', 'one time password', 'verification code', 'security code', 'confirm otp', 'enter otp',
      'share otp', 'don\'t share otp', 'never share otp', 'otp received', 'otp sent',
      'dear customer', 'dear user', 'dear valued', 'account holder', 'update now',
      'last chance', 'act now', 'immediate action', 'limited time', 'time bound',
      'verify your phone', 'mobile number', 'link aadhaar', 'aadhaar linked',
'complete kyc', 'update kyc now', 'kyc pending', 'kyc expired',
      'give me your name', 'tell me your name', 'your name please'
    ],
    weight: 15,
    emailSpecific: [
      'from:', 'reply-to', 'subject:', 'attachment', 'mailer-daemon', 'undeliverable'
    ],
    indicatorPhrases: [
      'suspended', 'verify', 'login', 'confirm', 'reset', 'urgent', 'security alert', 'account'
    ]
  },
  financialTheft: {
    keywords: [
      'otp', 'one time password', 'verification code', 'security code', 'confirm otp', 'enter otp',
      'share otp', 'don\'t share otp', 'never share otp', 'otp received', 'otp sent',
      'bank details', 'bank account number', 'ifsc code', 'account number', 'upi id', 'upi',
      'credit card', 'debit card', 'cvv', 'expiry date', 'card number', 'bill details',
      'save card', 'update card', 'link bank', 'add bank', 'verify bank', 'bank verification',
      'connect bank', 'link account', 'add account', 'bank aadhaar', 'aadhaar number',
      'pan number', 'pan card details', 'gst number', 'gstin', 'wallet verification',
      'kYC', 'kyc verification', 'complete kyc', 'verify kyc', 'update kyc',
      'payment details', 'billing info', 'billing address', 'shipping address',
      'razorpay', 'paytm', 'phonepe', 'gpay', 'paypal', 'stripe', 'payment gateway',
      'refund money', 'money refund', 'get refund', 'claim refund', 'track refund',
      'amazon pay', 'flipkart pay', 'swiggy', 'zomato', 'oyo', 'makemytrip',
      'electricity bill', 'gas bill', 'water bill', 'mobile bill', 'recharge',
      'bill payment', 'pay bill', 'clear dues', 'clear due', 'outstanding amount',
      'net banking', 'online banking', 'ibank', 'login banking', 'banking login',
      'atm card', 'atm pin', 'atm password', 'pin number', 'change pin',
      'wallet otp', 'payment otp', 'transaction otp', 'send otp', 'get otp',
      'link your bank', 'add your bank', 'bank account details', 'verify your bank',
      'confirm your account', 'validate your account', 'activate your account',
      'update your bank', 'refresh your bank', 'sync your bank',
      'receive payment', 'accept payment', 'payment received', 'money received',
      'send money', 'transfer money', 'instant transfer', 'quick transfer',
      'gift card', 'google play card', 'itunes card', 'apple card', 'amazon gift card',
      'voucher', 'gift voucher', 'shopping voucher', 'paytm gift', 'amazon pay gift',
      'electricity wallet', 'gas wallet', 'dth recharge', 'mobile recharge',
      'recharge now', 'add money', 'load money', 'top up', 'topup',
      'safe account', 'safe bank', 'secure account', 'verify account',
      'money transfer', 'fund transfer', 'neft', 'rtgs', 'imps',
      'beneficiary', 'add beneficiary', 'remove beneficiary', 'delete beneficiary',
      'udta', 'unique transaction', 'transaction id', 'utr number', 'ref number',
      'customer id', 'customer id number', 'customer support', 'help desk',
      'verify your identity', 'confirm your identity', 'identity proof',
      'address proof', 'age proof', 'income proof', 'documents',
      'upload documents', 'submit documents', 'send documents',
      'pan', 'gst', 'aadhaar card', 'aadhaar linked',
      'verify your mobile', 'verify your email', 'verify phone',
      'suspended account', 'blocked account', 'limited account', 'hold account',
      'restore account', 'activate account', 'unfreeze account',
      'account locked', 'account blocked', 'account hold',
      'click here to verify', 'click here to update', 'click here to confirm',
      'link to verify', 'link to update', 'link to confirm',
      'verify now or lose', 'confirm or account closed',
      'update within 24 hours', 'verify within 48 hours', 'confirm within 24',
      'immediate verification needed', 'verify immediately',
      'security check', 'safety check', 'verify safety',
      'authorised', 'authorisation', 'authorise', 'authorised person',
      'representative', 'official representative', 'authorised agent',
      'call now', 'call us', 'call this number', 'reach us',
      'customer care', 'customercare', 'customer care number',
      'toll free', 'tollfree', 'helpline', 'help line',
      '24/7 support', 'round the clock', 'anytime support',
      'don\'t ignore', 'don\'t delay', 'don\'t wait',
      'last warning', 'final warning', 'serious warning',
      'mandatory', 'compulsory', 'required', 'necessary',
      'failure to comply', 'non compliance', 'noncompliance',
      'penalty', 'penalty charge', 'fine', 'late fee',
      'close account', 'suspend account', 'terminate account',
      'action required', 'attention required', 'urgent attention',
      'account will be', 'account may be', 'account could be',
      'permanent suspension', 'temporary suspension', 'indefinite suspension',
      'link', 'click the link', 'tap here', 'open link',
      'login link', 'verify link', 'reset link', 'update link',
      'fake website', 'fake link', 'fake page', 'fake form',
      'fill form', 'fill details', 'enter details', 'submit details',
      'form', 'online form', 'web form', 'google form',
      'username', 'user id', 'user name', 'login id',
      'password', 'passcode', 'secret code', 'access code',
      'pin', 'pincode', 'm pin', 'transaction pin', 'atm pin',
      'qr code', 'scan qr', 'scan this', 'scan and pay',
      'upi qr', 'payment qr', 'scan qr code',
      'amount to pay', 'pay amount', 'enter amount',
      'total amount', 'payable amount', 'amount due',
      'rupees', 'rs', 'inr', '₹', ' INR',
      'five thousand', 'ten thousand', 'fifty thousand', 'one lakh', 'two lakh',
      '5000', '10000', '50000', '100000', '200000',
      'processing fee', 'processing charges', 'transaction fee',
      'commission', 'brokerage', 'service charge', 'service fee',
      'admin charge', 'handling fee', 'convenience charge',
      'min amount', 'max amount', 'minimum', 'maximum',
      'win prize', 'won prize', 'prize money', 'cash prize',
      'lottery', 'lucky draw', 'lucky winner', 'winner selected',
      'congratulations', 'congrats', 'congrats you',
      'prize claim', 'claim prize', 'claim now', 'claim amount',
      'free gift', 'free offer', 'free deal', 'free recharge',
      'complimentary', 'bonus cash', 'bonus money', 'extra cash',
      'cashback', 'cash back', 'get cashback', 'earn cashback',
      'scratch card', 'scratch and win', 'scratch card prize',
      'spin and win', 'wheel of fortune', 'lucky spin',
      'refer and earn', 'referral bonus', 'invite bonus',
      'signup bonus', 'register bonus', 'joining bonus',
      'first transaction', 'first payment', 'first time',
      'limited period', 'limited offer', 'limited time only',
      'exclusive offer', 'special offer', 'flash sale',
      'big sale', 'mega sale', 'grand sale',
      'discount offer', 'discount coupon', 'coupon code',
      'apply coupon', 'enter coupon', 'use coupon',
      'promo code', 'promocode', 'promotional code',
      'gift coupon', 'gift code', 'voucher code'
    ],
    weight: 25,
    emailSpecific: [
      'bank', 'payment', 'refund', 'transaction', 'otp', 'money'
    ]
  },
  spam: {
    keywords: [
      'free money', 'lottery winner', 'congratulations you won', 'click here to claim',
      'act now', 'limited time offer', 'exclusive deal', 'discount', 'unsubscribe',
      'you have been selected', 'claim your prize', 'free gift', 'bonus', 'cash prize',
      'million dollars', 'inheritance', 'next of kin', 'deceased', 'million dollar',
      'prize', 'winner', 'selected', 'lucky winner', 'claim now',
      'free recharge', 'free data', 'free talktime', 'free sim', 'free phone',
      'win iphone', 'win samsung', 'win iphone 15', 'win laptop', 'win car',
      'buy now', 'order now', 'shop now', 'limited stock', 'selling fast',
      'best price', 'lowest price', 'cheapest', 'best deal', 'hot deal',
      'clearance', 'clearance sale', 'warehouse sale', 'end of sale',
      '70% off', '80% off', '90% off', 'flat 50%', 'flat 70%',
      'free delivery', 'free shipping', 'cash on delivery', 'cod',
      'today only', 'last day', 'ending soon', 'final hours',
      'huge savings', 'massive discount', 'unbeatable price',
      'buy 1 get 1', 'bogo', 'bogof', 'free item',
      'unsubscribe here', 'click to unsubscribe', 'manage subscription',
      'you are subscribed', 'weekly newsletter', 'daily deals',
      'click below', 'click here', 'tap here', 'open this', 'visit now',
      'click to call', 'tap to call', 'call now', 'dial now',
      'join now', 'sign up now', 'register now', 'register free',
      'signup free', 'sign up free', 'free signup', 'free sign up',
      'limited time', 'limited period', 'offer ends', 'sale ends',
      'only today', 'today only', 'hours left', 'minutes left',
      'free access', 'free login', 'free account', 'free membership',
      'premium free', 'vip free', 'gold free',
      'update profile', 'complete profile', 'verify profile',
      'confirm email', 'confirm phone', 'confirm identity',
      'verify email', 'verify phone', 'verify identity',
      'validate email', 'validate phone', 'validate account',
      'activate account', 'activate now', 'activate email',
      'lock account', 'unlock account', 'secure account',
      'password expired', 'password expiring', 'password will expire',
      'account will expire', 'account expiring', 'subscription expiring',
      'renew now', 'renewal now', 'auto renew', 'auto-renew',
      'special promo', 'special discount', 'special offer', 'special deal',
      'flash sale', 'flash deal', 'lightning deal', 'deal of the day',
      'doorbuster', 'door buster', 'doorbuster deal',
      'save big', 'save more', 'save upto 90%', 'save upto 80%',
      'upto 70% off', 'upto 60% off', 'upto 50% off',
      'minimum 50% off', 'minimum 40% off', 'minimum 30% off',
      'extra 10%', 'extra 20%', 'extra 30%', 'extra 50%',
      'super savings', 'mega savings', 'big savings', 'huge savings',
      'free trial', 'try free', 'trial free', 'free try',
      'cancel anytime', 'no commitment', 'no contract', 'no hidden fees',
      'money back guarantee', 'refund guarantee', 'full refund',
      '100% refund', 'double money back', 'money back',
      'lowest price guarantee', 'price match guarantee',
      'best price promise', 'price promise', 'price guarantee',
      'authentic', '100% authentic', 'genuine', 'original',
      'free shipping worldwide', 'shipping worldwide', 'global shipping',
      'delivered to your door', 'home delivery', 'door delivery',
      'cod available', 'cash on delivery available',
      'easy returns', 'hassle free returns', 'free returns',
      'return policy', 'return within', 'exchange policy',
      'warranty', 'warranty included', 'warranty card',
      '1 year warranty', '2 year warranty', 'lifetime warranty',
      'brand new', '100% new', 'seal packed', 'factory sealed',
      'imported', 'imported from usa', 'imported from uk', 'imported from dubai',
      'authentic product', 'original product', 'genuine product'
    ],
    weight: 12
  },
  malware: {
    keywords: [
      'download now', 'install software', 'open attachment', 'click to download',
      'update your software', 'download exe', 'run script', 'enable macros',
      'install app', 'download file', 'open file', 'unzip', 'extract', 'payload',
      'malicious', 'virus scan', 'infected', 'corrupted file',
      'click to install', 'install now', 'download app', 'get app',
      'update app', 'update now', 'new version', 'latest version',
      'security update', 'urgent update', 'mandatory update',
      'enable unknown sources', 'allow unknown apps', 'disable security',
      'bypass antivirus', 'disable firewall', 'turn off security',
      'root access', 'jailbreak', 'unlock bootloader',
      'open link in new tab', 'download pdf', 'download doc',
      'click to view', 'view document', 'preview file',
      'invoice attached', 'bill attached', 'statement attached',
      'receipt attached', 'booking confirmation', 'ticket attached',
      'your file', 'your document', 'your invoice', 'your bill',
      'important document', 'confidential file', 'private file',
      'click to open', 'open now', 'view now', 'download now',
      'install and run', 'install and open', 'download and install',
      'run as administrator', 'run as admin', 'admin access',
      'grant admin', 'give admin', 'admin privileges',
      'full access', 'root privileges', 'super user',
      'allow popup', 'allow popups', 'enable popup',
      'click allow', 'click permit', 'allow redirect',
      'follow instructions', 'follow steps', 'do as shown',
      'step 1', 'step 2', 'step 3', 'step 4', 'follow steps',
      'download link below', 'download button below',
      'click download button', 'click install button',
      'install button', 'download button', 'update button',
      'upgrade now', 'upgrade free', 'upgrade to premium',
      'new update available', 'critical update', 'important update',
      'your version is old', 'version outdated', 'update required',
      'force close', 'force stop', 'clear cache', 'clear data',
      'uninstall and reinstall', 'delete and download',
      'remove and install', 'fresh install', 'new install',
      'download from link', 'download using link', 'download via link',
      'click here to download', 'click here to install',
      'tap to download', 'tap to install', 'tap to open',
      'download completed', 'install completed', 'update completed',
      'restart now', 'reboot now', 'restart device',
      'file attached below', 'document attached',
      'click on attachment', 'open the attachment',
      'save attachment', 'save file', 'save document',
      'file name', 'document name', 'download name',
      '.exe', '.bat', '.vbs', '.cmd', '.scr', '.pif',
      '.zip', '.rar', '.7z', '.tar', '.gz',
      '.apk', '.ipa', '.app', '.dmg',
      '.msi', '.msp', '.mst',
      '.js', '.jse', '.vbe', '.vbs',
      '.sh', '.bash', '.bin',
      '.jar', '.class',
      'macro enabled', 'enable content', 'enable editing',
      'click to enable', 'click to activate',
      'protected view', 'enable protected view',
      'security warning', 'security notice', 'warning',
      'this file', 'that file', 'the file',
      'attached file', 'attached document',
      'downloaded file', 'uploaded file',
      'shared file', 'received file',
      'click this link', 'click that link', 'click link',
      'open link', 'visit link', 'go to link',
      'follow link', 'use link', 'proceed link',
      'redirecting', 'redirect', 'auto redirect',
      'you are being redirected', 'please wait redirecting',
      'loading', 'please wait', 'do not close',
      'do not refresh', 'do not go back', 'do not close window'
    ],
    weight: 18,
    emailSpecific: [
      'attachment', 'attached', 'download', 'exe', 'zip', 'rar', 'bat', 'cmd', 'scr', 'vbs'
    ]
  },
  scam: {
    keywords: [
      'wire transfer', 'send money', 'western union', 'bitcoin wallet', 'cryptocurrency',
      'invest now', 'double your money', 'guaranteed returns', 'risk free', 'high profit',
      'online investment', 'trading platform', 'forex', 'nuclear', 'prince of nigeria',
      'inheritance', 'next of kin', 'unclaimed funds', 'million dollars', 'bank transfer',
      'gift card', 'itunes card', 'google play card', 'refund', 'compensation', 'abandoned',
      'consignment', 'beneficiary', 'urgent assistance',
      'you have been selected', 'selected for', 'chosen for',
      'opportunity of a lifetime', 'once in a lifetime', 'rare opportunity',
      'make money fast', 'earn from home', 'work from home', 'part time job',
      'easy money', 'quick money', 'fast cash', 'instant cash',
      'investment opportunity', 'business opportunity', 'money making',
      'mlm', 'network marketing', 'pyramid scheme', 'ponzi',
      'bitcoin investment', 'crypto investment', 'crypto trading',
      'forex trading', 'stock trading', 'share trading', 'intraday trading',
      'binary options', 'binary trading', 'iq option', 'olymptrade',
      'quikr', 'olx', 'sell used', 'buyer ready', 'immediate buyer',
      'car for sale', 'bike for sale', 'property for sale', 'flat for sale',
      'rent now', 'rent flat', 'rent apartment', 'pg available',
      'job vacancy', 'job opening', 'hiring now', 'walk in interview',
      'salary upto', 'earn upto', 'monthly income', 'daily income',
      'work online', 'online work', 'data entry', 'typing job',
      'simple work', 'easy work', 'home based work',
      'registration fee', 'joining fee', 'security deposit', 'advance',
      'processing fee', 'admin fee', 'service charge',
      'refundable deposit', 'security amount', 'token amount',
      'gift voucher', 'gift card', 'shopping voucher',
      'winner', 'you won', 'congratulations', 'congrats',
      'claim now', 'claim prize', 'collect prize', 'receive prize',
      'lottery', 'lucky draw', 'raffle', 'raffle winner',
      'international caller', 'foreign caller', 'uk call', 'usa call',
      'prince', 'royal family', 'royalty', 'oil money',
      'trapped money', 'trapped funds', 'blocked money',
      'diplomat', 'diplomatic bag', 'courier package',
      'package stuck', 'customs duty', 'clearance fee',
      'advance payment', 'advance fee', 'advance charges',
      'meet your match', 'find your partner', 'dating site',
      'single near you', 'girls near you', 'boys near you',
      'hot singles', 'hot girls', 'adult dating', 'escort service',
      'call girls', 'escort girls', 'party girls', 'models',
      'premium dating', 'vip dating', 'gold dating',
      'meet women', 'meet girls', 'meet singles',
      'video call girls', 'live girls', 'webcam girls',
      'adult fun', 'fun time', 'good time', 'great time',
      'spa service', 'massage service', 'body massage',
      'happy ending', 'happy massage', 'sensual massage',
      'russian model', 'foreign model', 'international model',
      'sugar daddy', 'sugar baby', 'sugar relationship',
      'allowance', 'monthly allowance', 'weekly allowance',
      'sponsored date', 'paid date', 'gift date',
      'fiverr', 'upwork', 'freelancer', 'freelance',
      'work from anywhere', 'remote work', 'remote job',
      'data entry job', 'typing job', 'copy paste job',
      'simple typing', 'easy typing', 'online typing',
      'earn 5000 daily', 'earn 10000 weekly', 'earn 50000 monthly',
      'no experience needed', 'freshers welcome', 'fresher can apply',
      'students welcome', 'housewives welcome', 'anyone can do',
      'part time', 'full time', 'temporary', 'permanent',
      'job offer', 'job interview', 'intercall', 'interview call',
      'selected candidate', 'selected applicant', 'shortlisted',
      'candidates list', 'applicants list', 'waitlist',
      'interview scheduled', 'interview fixed', 'interview date',
      'report to', 'report at', 'present at',
      'join immediately', 'join today', 'join now',
      'selected for job', 'offer letter', 'appointment letter',
      'salary letter', 'joining letter', 'offer received',
      'congratulations on selection', 'congratulations on selection',
      'salary 50000', 'salary 40000', 'salary 30000',
      'salary 50000 per month', 'salary 40000 per month',
      'incentive', 'bonus', 'perks', 'benefits',
      'travel allowance', 'food allowance', 'accommodation',
      'free transport', 'free cab', 'free shuttle',
      'company car', 'company bike', 'company mobile',
      'earn 1 lakh', 'earn 2 lakhs', 'earn 5 lakhs',
      'monthly 1 lakh', 'monthly 2 lakhs', 'monthly 5 lakhs',
      'yearly 10 lakhs', 'yearly 20 lakhs', 'yearly 50 lakhs',
      'profit sharing', 'revenue share', 'commission base',
      'fixed salary', 'variable salary', 'performance pay',
      'target based', 'incentive based', 'bonus based',
      'no target', 'no pressure', 'easy target',
      'achievable target', 'simple target',
      'work life balance', 'flexi timing', 'flexible hours',
      '5 days week', '6 days week', 'weekend off',
      'saturday sunday off', 'only 5 days',
      'morning shift', 'evening shift', 'night shift',
      'day shift', 'night shift', 'rotational shift',
      'work from home', 'work from office', 'hybrid work',
      'remote work', 'office work', 'field work',
      'field job', 'sales job', 'marketing job',
      'business development', 'bd', 'business partner',
      'partner program', 'partner opportunity',
      'become partner', 'business partner wanted',
      'investment partner', 'financing partner',
      'loan', 'apply for loan', 'personal loan', 'business loan',
      'loan approval', 'loan sanctioned', 'loan disburse',
      'instant loan', 'quick loan', 'fast loan', 'express loan',
      'no documents', 'no collateral', 'no guarantee',
      'no security', 'unsecured loan', 'signature loan',
      'low interest', 'low emi', 'easy emi', 'zero interest',
      'interest free', 'interest free emi', 'free emi',
      'credit card', 'apply credit card', 'get credit card',
      'free credit card', 'lifetime free card', 'no annual fee',
      'cash back card', 'rewards card', 'points card',
      'loan amount 50000', 'loan amount 100000', 'loan amount 500000',
      'loan 5 lakh', 'loan 10 lakh', 'loan 20 lakh',
      'eligibility', 'check eligibility', 'verify eligibility',
      'eligible', 'qualify', 'qualifying', 'approval',
      'pre approved', 'prequalified', 'preapproved offer',
      'limited offer', 'limited time', 'offer ending',
      'apply now', 'apply today', 'apply immediately',
      'last chance', 'final chance', 'last opportunity',
      'offer for you', 'special for you', 'exclusive for you',
      'only for you', 'just for you', 'because you',
      'valued customer', 'valued client', 'premium customer',
      'vip customer', 'gold customer', 'platinum customer',
      'old customer', 'existing customer', 'returning customer',
      'loyal customer', 'favorite customer', 'special customer',
      'we miss you', 'miss you', 'come back',
      'welcome back', 'good to see you', 'great to see you',
      'join again', 'register again', 'login again',
      'reactivate', 'reactivate account', 'activate again',
      'verify again', 'confirm again', 'reconfirm',
      'resend otp', 'resend code', 'get new code',
      'new code', 'fresh code', 'another code',
      'code not working', 'code expired', 'code invalid',
      'resend link', 'regenerate link', 'new link',
      'click resend', 'click to resend', 'request again',
      'request new', 'generate new', 'create new',
      'otp sent', 'code sent', 'link sent',
      'check spam', 'check junk', 'check promotions',
      'email not received', 'email not coming',
      'add to contacts', 'save contact', 'save number',
      'save sender', 'add sender', 'whitelist',
      'mark not spam', 'mark as safe', 'not junk'
    ],
    weight: 16
  },
  harassment: {
    keywords: [
      'kill you', 'i will hurt', 'i know where you', 'threat', 'abuse', 'slur',
      'offensive language', 'hate', 'harassment', ' stalking', 'intimidate', 'threaten',
      'bully', 'humiliate', 'insult', 'defame', 'blackmail', 'exposed', 'leaked',
      'shame you', 'ruin your reputation', 'disgrace', 'doxing',
      'i will kill', 'i will rape', 'i will beat', 'i will hit',
      'die', 'death', 'kill yourself', 'commit suicide',
      'i know your address', 'i know where you live', 'i found you',
      'your photos', 'your videos', 'your private', 'your intimate',
      'leak your photos', 'publish your videos', 'expose you',
      'shame on you', 'you are worthless', 'you are nothing',
      'nobody likes you', 'everyone hates you', 'go away',
      'shut up', 'quiet', 'stop talking', 'stop responding',
      'you are fired', 'you are sacked', 'you are fired from job',
      'police is coming', 'i will call police', 'i will report you',
      'court case', 'i will sue', 'legal action', 'court notice',
      'rumours', 'rumors about you', 'spread rumors', 'talk about you',
      'fake account', 'fake profile', 'fake id', 'fake person',
      'account hacked', 'profile hacked', 'id hacked',
      'spam', 'fake news', 'false information', 'lies about you',
      'ugly', 'fat', 'skinny', 'short', 'tall', 'fair', 'dark',
      'loser', 'failure', 'idiot', 'stupid', 'dumb', 'dumbass',
      'fool', 'moron', 'imbecile', 'retard', 'retarded',
      'pathetic', 'hopeless', 'useless', 'good for nothing',
      'worthless', '废物', '无用', '垃圾',
      'bastard', 'son of a bitch', 'son of whore',
      'fuck you', 'fuck off', 'fuck you very much',
      'shit', 'shitty', 'bullshit', 'shut the fuck up',
      'damn', 'damned', 'goddamn', 'god damn',
      'ass', 'asshole', 'dick', 'cock', 'pussy', 'cunt',
      'whore', 'slut', 'prostitute', 'ho', 'hoe',
      'nasty', 'nastiest', 'dirty', 'dirty minded',
      'pervert', 'perverted', 'creep', 'creepy',
      'molester', 'molesting', 'sexual harass', 'eve teasing',
      'acid attack', 'rape threat', 'murder threat',
      'warning', 'final warning', 'last warning',
      'consider this', 'mark my words', 'remember this',
      'you will regret', 'you will suffer', 'you will pay',
      'pay back', 'pay the price', 'make you pay',
      'i have proof', 'i have evidence', 'i have videos',
      'your secrets', 'your hidden', 'your truth',
      'expose truth', 'reveal truth', 'tell truth',
      'everyone will know', 'whole world will know',
      'viral', 'viral video', 'viral post',
      'share your video', 'share your photo',
      'post online', 'upload online', 'publish everywhere',
      'social media', 'facebook', 'instagram', 'twitter',
      'whatsapp status', 'whatsapp story', 'status story',
      'tag you', 'mention you', 'post about you',
      'comment on', 'reply to', 'quote tweet',
      'dm', 'direct message', 'private message',
      'call out', 'call out post', 'call out story',
      'expose account', 'expose profile', 'expose id',
      'report account', 'suspend account', 'ban account',
      'block you', 'ban you', 'suspend you',
      'cancel you', 'cancels', 'cancel culture',
      'toxic', 'toxic person', 'toxic behavior',
      'gaslight', 'gaslighting', 'manipulate',
      'manipulator', 'controlling', 'controlling behavior',
      'jealous', 'jealousy', 'envy', 'envious',
      'backstabber', 'fake friend', 'two faced',
      'betray', 'betrayal', 'backstab', 'stab in back',
      'enemy', 'not friend', 'fake vibes',
      'red flag', 'red flags', 'warning signs',
      'run away', 'stay away', 'stay clear',
      'block and delete', 'unfollow', 'unfriend',
      'no contact', 'nc', 'no contact order',
      'leave me alone', 'leave them alone', 'let me be',
      'go to hell', 'rot in hell', 'burn in hell',
      'curse', 'cursed', 'bad luck', 'evil eye',
      'pray for death', 'wish death', 'hope you die',
      'never talk to me', 'never contact me',
      'worse', 'worst', 'terrible', 'horrible',
      'nightmare', 'bad dream', 'bad experience',
      'trauma', 'traumatized', 'emotional damage',
      'mental health', 'anxiety', 'depression',
      'break down', 'breakdown', 'panic attack',
      'self harm', 'self harm', 'cut myself',
      'suicidal', 'suicide thoughts', 'want to die'
    ],
    weight: 20
  },
  socialEngineering: {
    keywords: [
      'tech support', 'microsoft support', 'apple support', 'google support', 'amazon support',
      'customer support', 'helpdesk', 'support team', 'remote access', 'teamviewer',
      'anydesk', 'screen share', 'remote desktop', 'allow access', ' grammarly',
      'windows update', 'your device', 'hacker', 'security breach', 'unauthorized access',
      'impersonating', 'fake support', 'phishing call', 'callback',
      'call from microsoft', 'call from windows', 'call from apple',
      'call from google', 'call from amazon', 'call from bank',
      'microsoft representative', 'windows representative', 'apple representative',
      'technical support', 'technical help', 'technical assistance',
      'computer slow', 'computer infected', 'laptop infected',
      'system infected', 'device infected', 'phone infected',
      'virus detected', 'malware detected', 'threat detected',
      'your computer', 'your laptop', 'your mobile', 'your phone',
      'device at risk', 'device in danger', 'system at risk',
      'remote repair', 'remote fix', 'online repair',
      'click to fix', 'download fix', 'install fix',
      'fix now', 'fix now', 'repair now', 'clean now',
      'quick support', 'instant support', 'immediate help',
      '24/7 helpline', '24x7 support', 'anytime help',
      'toll free number', 'toll free call', 'free call',
      'helpline number', 'support number', 'customer care number',
      'authorised technician', 'certified technician', 'trained technician',
      'engineer', 'specialist', 'expert', 'professional',
      'your computer is slow', 'your computer is old', 'your computer is dying',
      'update now or else', 'update now or your', 'update or hack',
      'your data is at risk', 'your files are at risk',
      'backup now', 'backup your data', 'backup immediately',
      'unusual activity detected', 'suspicious activity', 'unauthorized login',
      'recent login', 'new login', 'login from', 'new device',
      'account activity', 'unusual login', 'unknown device',
      'reset your password', 'reset now', 'password reset',
      'verify your account', 'verify now', 'confirm your account',
      'link your account', 'sync your account', 'connect your account',
      'your account is not safe', 'your account is at risk',
      'security warning', 'security alert', 'security notification',
      'critical security', 'important security', 'urgent security',
      'your system may crash', 'your system will crash',
      'hard drive failing', 'hard drive dying', 'storage failing',
      'install our app', 'download our app', 'use our app',
      'switch to our', 'move to our', 'come to our platform',
      'we are the best', 'we are number 1', 'top company',
      'ranked 1', 'number 1', 'best support', 'best service',
      'do you need help', 'let me help you', 'i can help you',
      'let me show you', 'let me teach you', 'follow me',
      'click this link', 'click the link', 'go to link',
      'type this', 'enter this', 'enter that', 'type this code',
      'enter code', 'enter pin', 'enter password',
      'just do this', 'just click', 'just enter',
      'say yes', 'say confirm', 'confirm yes', 'agree yes',
      'allow access', 'allow installation', 'allow download',
      'grant permission', 'give permission', 'allow permission',
      'enable feature', 'turn on feature', 'activate feature',
      'call our helpline', 'call our support', 'call our team',
      'reach out', 'reach us', 'get in touch', 'contact us',
      'forget password', 'forgotten password', 'lost password',
      'reset password link', 'password reset link',
      'change password', 'update password', 'modify password',
      'new password', 'set password', 'create password',
      'confirm password', 'verify password', 'validate password',
      'password mismatch', 'password incorrect', 'wrong password',
      'try again', 'attempt again', 'retry login',
      'login successful', 'login failed', 'login error',
      'authentication failed', 'authentication error',
      'session expired', 'session timeout', 'login timeout',
      'relogin', 'login again', 'login fresh',
      'verify yourself', 'authenticate yourself', 'prove yourself',
      'identity verification', 'identity check',
      'verify device', 'device verification', 'confirm device',
      'approve device', 'authorize device', 'allow device',
      'trusted device', 'remember device', 'save device',
      'login history', 'login activity', 'account activity',
      'recent activity', 'latest activity', 'last activity',
      'security check', 'safety check', 'verify safety',
      'verify email address', 'confirm email address',
      'email verification', 'email confirm', 'verify phone number',
      'phone verification', 'phone confirm', 'phone validation',
      'sms verification', 'sms code', 'sms confirm',
      'verify social', 'social verification', 'social account verify',
      '2 step verification', '2 step', 'two step',
      'two factor', 'two factor authentication', '2fa',
      'multi factor', 'multi factor authentication', 'mfa',
      'confirm 2fa', 'verify 2fa', 'complete 2fa',
      'authenticator', 'authenticator app', 'google authenticator',
      'microsoft authenticator', 'authy',
      'verification needed', 'verification required',
      'complete verification', 'finish verification',
      'submit verification', 'send verification',
      'verification pending', 'verification incomplete',
      'verification failed', 'verification unsuccessful',
      'verification error', 'verification issue',
      'verification success', 'verification complete',
      'please verify', 'must verify', 'required to verify',
      'verify to continue', 'verify to proceed',
      'click to verify', 'tap to verify', 'open to verify',
      'call to verify', 'sms to verify',
      'we called you', 'we will call', 'dial us back',
      'missed call', 'missed call from', 'missed call give',
      'callback requested', 'callback needed', 'callback required',
      'call back now', 'call us now', 'ring us now',
      'dial now', 'dial in', 'connect now',
      'join call', 'join conference', 'join meeting',
      'video call', 'video chat', 'video meeting',
      'voice call', 'voice chat', 'voice conference',
      'conference call', 'conference meeting',
      'online meeting', 'online call', 'online chat',
      'meet now', 'chat now', 'talk now',
      'join us now', 'be part of', 'become part',
      'invite friend', 'invite others', 'invite more',
      'share invite', 'send invite', 'forward invite',
      'invitation', 'join invitation', 'accept invitation',
      'decline invitation', 'reject invitation',
      'invite link', 'invite code', 'invite url',
      'registration link', 'registration form', 'registration here',
      'sign up link', 'sign up form', 'sign up page',
      'login link', 'login page', 'login portal',
      'portal link', 'portal page', 'portal url',
      'admin panel', 'admin login', 'admin portal',
      'control panel', 'control access',
      'dashboard', 'dashboard login',
      'member area', 'member login', 'member portal',
      'client area', 'client login', 'client portal',
      'user area', 'user login', 'user portal',
      'my account', 'my profile', 'my page',
      'account settings', 'profile settings',
      'edit profile', 'update profile', 'change profile',
      'personal info', 'personal details', 'personal data',
      'profile info', 'profile details', 'profile data',
      'account info', 'account details', 'account data',
      'billing info', 'billing details', 'billing data',
      'payment info', 'payment details', 'payment data',
      'shipping info', 'shipping details', 'shipping address',
      'delivery address', 'delivery details',
      'contact info', 'contact details', 'contact data',
      'phone number', 'mobile number', 'contact number',
      'email address', 'mail address', 'mail id',
      'social media handle', 'social handle', 'social id',
      'instagram handle', 'twitter handle', 'facebook handle',
      'linkedin profile', 'linkedin url',
      'website url', 'site url', 'web address',
      'ip address', 'device ip', 'system ip',
      'mac address', 'device mac', 'network mac',
      'serial number', 'device serial', 'product serial',
      'imei number', 'device imei', 'phone imei',
      'activation key', 'product key', 'license key',
      'registration key', 'registration code', 'serial key',
      'login key', 'access key', 'auth key',
      'api key', 'api token', 'api secret',
      'secret key', 'secret token', 'secret code',
      'public key', 'private key', 'encryption key',
      'access token', 'auth token', 'bearer token',
      'session token', 'session id', 'session key',
      'refresh token', 'refresh key',
      'verification token', 'verification key',
      'security token', 'security code', 'security key'
    ],
    weight: 14
  },
  fraud: {
    keywords: [
      'fake', 'fake identity', 'impersonate', 'scam artist', 'fraud', 'deceptive',
      'misleading', 'fake website', 'clone site', 'fake login', 'clone', 'phony',
      'counterfeit', 'fake offer', 'too good to be true',
      'duplicate', 'replica', 'knockoff', 'knock off', 'imitation',
      'scam website', 'fraud website', 'fake store', 'scam store',
      'fake company', 'fraud company', 'shell company', 'front company',
      'scam call', 'fraud call', 'fake call', 'bogus call',
      'scam message', 'fraud message', 'fake message', 'bogus message',
      'scam email', 'fraud email', 'fake email', 'phishing email',
      'clone app', 'fake app', 'fraud app', 'malicious app',
      'fake login page', 'fake sign in', 'fake sign in page',
      'login page', 'sign in page', 'sign in here',
      'enter password here', 'enter details here',
      'your username', 'your password', 'your account',
      'verify password', 'confirm password',
      'password', 'secret', 'passcode', 'pin',
      'your money', 'your bank', 'your account',
      'transfer now', 'pay now', 'send now', 'done now',
      'dont wait', 'dont delay', 'limited time',
      'offer valid', 'offer expires', 'offer ending',
      'hurry', 'hurry up', 'be quick', 'quickly',
      'act fast', 'act now', 'fast action',
      'today only', 'limited period', 'only today',
      'special price', 'discount price', 'reduced price',
      'cheap price', 'lowest price', 'best price',
      'lowest ever', 'cheapest ever', 'best ever',
      'price reduced', 'price dropped', 'price cut',
      'discount', 'discounted', 'reduced', 'sale',
      'clearance', 'clearance sale', 'closeout',
      'bargain', 'deal', 'steal', 'giveaway',
      'free', 'freebie', 'complimentary',
      'win', 'won', 'winner', 'winning',
      'prize', 'reward', 'bonus', 'gift',
      'congratulations', 'congrats', 'congrats you',
      'you have been selected', 'you are the winner',
      'selected', 'chosen', 'picked', 'winner',
      'claim', 'claim now', 'claim your', 'claim prize',
      'receive', 'get now', 'get your', 'avail now',
      'lucky', 'lucky day', 'your lucky day',
      'lucky winner', 'lucky you', 'lucky person',
      'click below', 'click here', 'click now',
      'tap below', 'tap here', 'tap now',
      'open below', 'open here', 'open now',
      'visit below', 'visit here', 'visit now',
      'register below', 'register here', 'register now',
      'sign up below', 'sign up here', 'sign up now',
      'sign below', 'sign here', 'sign now',
      'log in below', 'log in here', 'log in now',
      'login below', 'login here', 'login now',
      'submit below', 'submit here', 'submit now',
      'fill below', 'fill here', 'fill now',
      'enter below', 'enter here', 'enter now',
      'type below', 'type here', 'type now',
      'apply below', 'apply here', 'apply now',
      'buy below', 'buy here', 'buy now',
      'order below', 'order here', 'order now',
      'purchase below', 'purchase here', 'purchase now',
      'shop below', 'shop here', 'shop now',
      'get below', 'get here', 'get now',
      'avail below', 'avail here', 'avail now',
      'don\'t miss', 'don\'t wait', 'don\'t delay',
      'miss out', 'miss this', 'miss out on',
      'limited offer', 'limited deal', 'limited time',
      'once in a lifetime', 'rare opportunity',
      'exclusive', 'exclusive offer', 'exclusive deal',
      'invitation only', 'invitation only',
      'invite only', 'invite only', 'invite only',
      'membership only', 'members only', 'vip only',
      'premium', 'premium offer', 'premium deal',
      'vip', 'vip offer', 'vip deal',
      'gold', 'gold offer', 'gold deal',
      'platinum', 'platinum offer', 'platinum deal',
      'diamond', 'diamond offer', 'diamond deal',
      'black card', 'black member', 'black tier',
      'silver', 'silver offer', 'silver deal',
      'bronze', 'bronze offer', 'bronze deal',
      'tier', 'tier level', 'tier status',
      'level', 'level up', 'upgrade level',
      'rank', 'rank up', 'promote rank',
      'status', 'VIP status', 'premium status',
      'membership', 'membership status',
      'subscription', 'subscription status',
      'member', 'member benefits', 'member perks',
      'subscriber', 'subscriber benefits',
      'customer', 'customer benefits', 'customer perks',
      'client', 'client benefits', 'client perks',
      'user', 'user benefits', 'user perks',
      'account holder', 'account holder benefits',
      'card holder', 'card holder benefits',
      'reward points', 'reward credits', 'reward balance',
      'points', 'credits', 'balance',
      'cash back', 'cashback', 'money back',
      'refund', 'refund policy', 'money back guarantee',
      'return', 'return policy', 'easy returns',
      'exchange', 'exchange policy', 'easy exchange',
      'warranty', 'warranty policy', 'warranty card',
      'guarantee', 'guarantee policy', 'guarantee card',
      'protection', 'protection plan', 'protection policy',
      'insurance', 'insurance plan', 'insurance policy',
      'cover', 'cover plan', 'cover policy',
      'plan', 'plan details', 'plan info',
      'package', 'package details', 'package info',
      'deal', 'deal details', 'deal info',
      'offer', 'offer details', 'offer info',
      'promo', 'promo details', 'promo info',
      'campaign', 'campaign details', 'campaign info',
      'event', 'event details', 'event info',
      'sale', 'sale details', 'sale info',
      'discount', 'discount details', 'discount info',
      'promotion', 'promotion details', 'promotion info',
      'special', 'special details', 'special info',
      'exclusive', 'exclusive details', 'exclusive info',
      'limited', 'limited details', 'limited info',
      'bonus', 'bonus details', 'bonus info',
      'gift', 'gift details', 'gift info',
      'prize', 'prize details', 'prize info',
      'reward', 'reward details', 'reward info',
      'winner', 'winner details', 'winner info',
      'selected', 'selected details', 'selected info',
      'chosen', 'chosen details', 'chosen info',
      'picked', 'picked details', 'picked info'
    ],
    weight: 13
  },
  misinformation: {
    keywords: [
      'fake news', 'clickbait', 'conspiracy', 'unverified claim', 'hoax', 'rumour',
      'rumor', 'breaking', 'shocking', 'you won\'t believe', 'secret cure', 'miracle',
      'natural cure', 'vaccine fake', '5g corona', 'conspiracy theory', 'exposed truth',
      'they don\'t want you to know', 'hidden truth', 'censored', 'suppressed',
      'they are hiding', 'government hiding', 'media hiding',
      'cover up', 'coverup', 'cover-up', 'coverup',
      'secret', 'secret story', 'hidden story',
      'exposed', 'exposed story', 'exposed truth',
      'leaked', 'leaked info', 'leaked news',
      'leak', 'leak story', 'leak news',
      'truth untold', 'truth hidden', 'truth suppressed',
      'breaking news', 'urgent news', 'important news',
      'must watch', 'must share', 'must see',
      'viral', 'viral video', 'viral post',
      'share this', 'share now', 'share fast',
      'spread the word', 'spread now', 'spread fast',
      'tell everyone', 'tell everybody',
      'forward to all', 'forward to friends',
      'urgent', 'urgent alert', 'urgent warning',
      'important', 'important info', 'important notice',
      'warning', 'warning sign', 'warning sign',
      'alert', 'alert message', 'alert notice',
      'danger', 'dangerous', 'danger warn',
      'threat', 'threat level', 'threat warning',
      'scam warning', 'fraud warning', 'scam alert',
      'new virus', 'new disease', 'new illness',
      'cure found', 'cure discovered', 'cure invented',
      'miracle cure', 'miracle medicine', 'miracle drug',
      'natural remedy', 'herbal cure', 'herbal remedy',
      'home remedy', 'home cure', 'homemade cure',
      'ancient cure', 'ancient remedy', 'ancient medicine',
      'secret cure', 'secret remedy', 'secret medicine',
      'hidden cure', 'hidden remedy', 'hidden medicine',
      'revelation', 'revelation story', 'shocking revelation',
      'exposing', 'exposing truth', 'exposing secrets',
      'secret exposed', 'secrets revealed', 'truth revealed',
      'they lied', 'lied to you', 'lied about',
      'lie', 'lies', 'false', 'falsely',
      'false claim', 'false story', 'false news',
      'misleading', 'misleading info', 'misleading story',
      'deception', 'deception story', 'deception truth',
      'deceptive', 'deceptive content', 'deceptive info',
      'untrue', 'untrue story', 'untrue claim',
      'incorrect', 'incorrect info', 'incorrect claim',
      'inaccurate', 'inaccurate info', 'inaccurate story',
      'unverified', 'unverified info', 'unverified claim',
      'unconfirmed', 'unconfirmed info', 'unconfirmed claim',
      'unsupported', 'unsupported claim', 'unsupported info',
      'baseless', 'baseless claim', 'baseless story',
      'fabricated', 'fabricated story', 'fabricated claim',
      'made up', 'made up story', 'made up news',
      'invented', 'invented story', 'invented news',
      'fictional', 'fictional story', 'fictional news',
      'hoax', 'hoax story', 'hoax news',
      'scam', 'scam story', 'scam news',
      'fraud', 'fraud story', 'fraud news',
      'trick', 'trick story', 'trick news',
      'con', 'con story', 'con news',
      'scheme', 'scheme story', 'scheme news',
      'plot', 'plot story', 'plot news',
      'agenda', 'agenda story', 'agenda news',
      'hidden agenda', 'agenda revealed',
      'satanic', 'satanic cult', 'satanic ritual',
      'cult', 'cult leader', 'cult group',
      'brainwashing', 'brainwash', 'mind control',
      'mind programming', 'programming',
      'chemical', 'chemical weapons', 'chemical attack',
      'biological', 'biological weapons', 'bio attack',
      'nuclear', 'nuclear weapons', 'nuclear attack',
      'radiation', 'radiation leak', 'radiation danger',
      'contaminated', 'contaminated food', 'contaminated water',
      'poisoned', 'poisoned food', 'poisoned water',
      'toxic', 'toxic food', 'toxic water',
      'dangerous chemical', 'dangerous substance',
      'harmful chemical', 'harmful substance',
      'deadly', 'deadly chemical', 'deadly substance',
      'lethal', 'lethal chemical', 'lethal substance',
      'carcinogenic', 'cancer causing', 'cancercausing',
      'cancer', 'cancer cure', 'cancer treatment',
      'aids', 'hiv', 'hiv cure', 'aids cure',
      ' Ebola ', 'ebola cure', 'ebola treatment',
      'cov-id', 'covid cure', 'covid treatment',
      'coronavirus', 'corona cure', 'corona treatment',
      'virus', 'virus cure', 'virus treatment',
      'disease', 'disease cure', 'disease treatment',
      'illness', 'illness cure', 'illness treatment',
      'health problem', 'health issue', 'health concern',
      'medical problem', 'medical issue', 'medical concern',
      'health warning', 'health alert', 'health notice',
      'medical warning', 'medical alert', 'medical notice',
      'doctors', 'doctor secret', 'doctor revealed',
      'scientists', 'scientist secret', 'scientist revealed',
      'researchers', 'research secret', 'research revealed',
      'study', 'study shows', 'study found',
      'research', 'research shows', 'research found',
      'evidence', 'evidence shows', 'evidence found',
      'proof', 'proof shows', 'proof found',
      'data', 'data shows', 'data found',
      'studies', 'studies show', 'studies found',
      'findings', 'findings show', 'findings reveal',
      'results', 'results show', 'results reveal',
      'conclusion', 'conclusion shows', 'conclusion reveal',
      'discovery', 'discovery shows', 'discovery reveal',
      'revelation', 'revelation shows', 'revelation reveal',
      'breaking discovery', 'breaking finding',
      'shocking discovery', 'shocking finding',
      'urgent discovery', 'urgent finding',
      'important discovery', 'important finding',
      'must know', 'must learn', 'must see',
      'must watch', 'must share', 'must spread',
      'everyone must know', 'everybody must know',
      'tell everyone', 'tell everybody',
      'share with all', 'share with everyone',
      'forward to all', 'forward to everybody',
      'send to all', 'send to everybody',
      'pass to all', 'pass to everybody',
      'spread the word', 'spread the truth',
      'share the truth', 'tell the truth',
      'expose the truth', 'reveal the truth',
      'the truth about', 'the truth is',
      'they don\'t tell you', 'they won\'t tell you',
      'media doesn\'t tell', 'media won\'t tell',
      'news doesn\'t tell', 'news won\'t tell',
      'government doesn\'t', 'government won\'t',
      'officials don\'t', 'officials won\'t',
      'experts don\'t', 'experts won\'t',
      'scientists don\'t', 'scientists won\'t',
      'doctors don\'t', 'doctors won\'t',
      'they hide', 'they are hiding',
      'hiding the truth', 'hiding facts',
      'suppressing', 'suppress the truth',
      'censoring', 'censor the truth',
      'banning', 'ban the truth',
      'blocking', 'block the truth',
      'silencing', 'silence the truth',
      'shutting up', 'shut up the truth',
      'not reporting', 'not report the truth',
      'covering up', 'cover up the truth',
      'keeping quiet', 'keep quiet about',
      'hush up', 'hush up the truth',
      'sweeping', 'sweep under the rug',
      'ignore', 'ignoring the truth',
      'neglect', 'neglecting the truth',
      'overlooking', 'overlook the truth',
      'missing', 'missing the truth',
      'forgetting', 'forget the truth',
      'hiding', 'hide the truth',
      'concealing', 'conceal the truth',
      'withholding', 'withhold the truth'
    ],
    weight: 10
  }
};

const TOXICITY_DICT = {
  extreme: {
    words: ['kill', 'murder', 'die', 'death', 'rape', 'molest', 'abuse physically', 'execute', 'assassinate', 'lynch', 'beastiality'],
    score: 95
  },
  severe: {
    words: ['hate', 'slur', 'racist', 'casteist', 'sexist', 'traitor', 'scum', 'filth', 'disgusting', 'disgrace', 'shame on you', 'pathetic', 'worthless', 'loser', 'deserve to die', 'go die', 'drop dead'],
    score: 80
  },
  high: {
    words: ['abuse', 'harass', 'threaten', 'intimidate', 'bully', 'humiliate', 'insult', 'stupid', 'idiot', 'moron', 'dumb', 'incompetent', 'liar', 'fraud', 'scam', 'cheat', 'con artist', 'blackmail', 'defame', 'threat', 'threaten', 'will be frozen', 'will be blocked', 'will be suspended', 'will be closed', 'will be cancelled', 'or else', 'otherwise', 'police will', 'court case', 'lawsuit', 'arrest', 'jail', ' imprisonment', 'legal action', 'sue you', 'complaint', 'fir', 'frozen', 'freeze', 'blocked', 'suspended', 'closed account', 'blocked account', 'locked'],
    score: 65
  },
  moderate: {
    words: ['annoying', 'frustrating', 'irritating', 'ridiculous', 'pathetic', 'awful', 'terrible', 'horrible', 'spam', 'scam', 'suspicious', 'fake', 'deceptive', 'misleading', 'manipulative', 'tricky', 'dishonest', 'unethical', 'immediately', 'urgent', 'act now', 'last chance', 'final warning', 'deadline', 'expire', 'expired', 'urgent action', 'limited time', 'time limit'],
    score: 45
  },
  mild: {
    words: ['fake', 'spam', 'misleading', 'suspicious', 'odd', 'strange', 'unusual', 'concerning', 'alarming', 'worrying'],
    score: 25
  }
};

const PROTECTION_TIPS = {
  phishing: [
    'Never click links directly in emails — go to the website manually by typing the URL',
    'Check the sender\'s email address carefully for misspellings or unusual domains',
    'Legitimate companies never ask for passwords, OTPs, or personal details via email',
    'Enable two-factor authentication (2FA) on all important accounts',
    'Report suspicious emails to the company\'s official fraud department'
  ],
  spam: [
    'Do not reply to or click any links in spam messages',
    'Use spam filters and mark spam messages as junk',
    'Never provide personal information to unknown senders',
    'Unsubscribe only from legitimate emails — suspicious ones just mark as spam',
    'Use a secondary email address for public signups to protect your primary inbox'
  ],
  malware: [
    'Never download attachments from unknown or unexpected senders',
    'Keep your OS, browser, and antivirus software updated',
    'Avoid enabling macros in documents from untrusted sources',
    'Use reputable antivirus/antimalware software and run regular scans',
    'Do not install software from pop-ups — always download from official sources'
  ],
  scam: [
    'Verify any financial opportunity through official channels before acting',
    'Never send money or gift cards to unknown individuals — no legitimate business asks this',
    'Search the offer/company name online along with "scam" to check reviews',
    'No legitimate prize requires you to pay fees to claim it',
    'If it sounds too good to be true, it almost certainly is'
  ],
  harassment: [
    'Do not engage with or respond to the harasser — this often escalates behaviour',
    'Block and report the sender on the platform (email, WhatsApp, etc.)',
    'Screenshot all evidence before blocking in case it is needed for a legal complaint',
    'File a complaint under IPC 503 (criminal intimidation) at your local police station',
    'If threats are severe or imminent, call 100 (police) or 112 (emergency services) immediately'
  ],
  socialEngineering: [
    'Microsoft, Google, Amazon etc. never make unsolicited calls asking for remote access',
    'Never give screen share access to unknown callers — genuine support teams do not cold call',
    'If someone claims to be from support, hang up and call the official number from the website',
    'Real tech companies will never ask for payment via gift cards or cryptocurrencies',
    'Install software updates only from official sources, not from pop-ups or links'
  ],
  fraud: [
    'Always verify identities through official and independent channels before trusting anyone',
    'Cross-check any financial request with a trusted person or official body',
    'Do not share Aadhaar, PAN, bank details, or OTPs with anyone over calls or messages',
    'If you suspect fraud, contact your bank immediately to freeze accounts',
    'File an FIR at the nearest police station or cyber crime cell'
  ],
  misinformation: [
    'Check the source — verify if the information comes from a credible, official outlet',
    'Cross-reference claims on fact-checking sites like boom.in, factcrescendo.com',
    'Look for the original source and check the date — old news is often reshared falsely',
    'Do not forward unverified messages — sharing false information is also an offence',
    'Report misinformation to the platform (WhatsApp, Facebook) and fact-checkers'
  ],
  financialTheft: [
    'NEVER share OTP, CVV, PIN, or debit/credit card details with anyone — not even bank staff',
    'Banks never ask for OTPs via call, SMS, or email — this is a scam',
    'Never enter card details on unknown websites — check for HTTPS and the Padlock icon',
    'If someone asks for OTP to receive money, it is a scam — no legitimate transaction needs OTP from receiver',
    'Enable transaction alerts and daily limits on your bank account',
    'Use virtual cards for online transactions when possible',
    'Regularly check your bank statements for unauthorized transactions',
    'Never save card details on browsers or unknown apps'
  ]
};

const WHAT_NOT_TO_DO = {
  phishing: [
    'Do NOT click the link provided in the email — even if it looks legitimate',
    'Do NOT enter your username, password, OTPs, or personal details on the linked page',
    'Do NOT reply to the email with any information',
    'Do NOT download or open any attachments',
    'Do NOT forward the email to others without warning them'
  ],
  spam: [
    'Do NOT reply to spam messages — it confirms your email/number is active',
    'Do NOT click any links in spam messages',
    'Do NOT call any phone numbers listed in suspicious messages',
    'Do NOT provide any personal or financial information',
    'Do NOT forward the message without clearly warning the recipient'
  ],
  malware: [
    'Do NOT download or open any attachments from unknown senders',
    'Do NOT enable macros in documents unless you are certain of the source',
    'Do NOT allow remote access to your device to unknown callers',
    'Do NOT install software from pop-ups or unverified websites',
    'Do NOT ignore antivirus warnings — take them seriously'
  ],
  scam: [
    'Do NOT send money via wire transfer, gift cards, or cryptocurrency to strangers',
    'Do NOT share your bank account or UPI details with unknown persons',
    'Do NOT invest in platforms that guarantee high returns with no risk',
    'Do NOT provide your Aadhaar, PAN, or KYC documents to unverified entities',
    'Do NOT share OTP or debit/credit card CVV with anyone'
  ],
  benign: [
    'Always verify the sender before clicking any links',
    'Keep your personal information private online',
    'Use official apps/websites for transactions',
    'Enable two-factor authentication where possible',
    'Regularly review your account statements'
  ],
  harassment: [
    'Do NOT respond to the harasser — engaging often encourages escalation',
    'Do NOT delete the messages — screenshots and records are evidence',
    'Do NOT share the messages publicly without context — it may worsen the situation',
    'Do NOT confront the harasser in person if threats are involved',
    'Do NOT ignore threats — even online threats can be prosecuted'
  ],
  socialEngineering: [
    'Do NOT give remote access (TeamViewer, AnyDesk) to anyone claiming to be support',
    'Do NOT install any software or app suggested by an unsolicited caller',
    'Do NOT share your screen during a call with unknown persons',
    'Do NOT provide UPI, bank, or card details to tech support callers',
    'Do NOT make payments for "free" services or "security checks"'
  ],
  fraud: [
    'Do NOT share OTP, PIN, password, or CVV with anyone — not even bank staff',
    'Do NOT transfer money to strangers without independent verification',
    'Do NOT click links in messages claiming to be from your bank',
    'Do NOT share Aadhaar or PAN copies unless KYC is done through official channels'
  ],
  financialTheft: [
    'Do NOT share OTP with ANYONE — not even bank officials, police, or family members',
    'Do NOT share CVV, card PIN, or ATM PIN with anyone',
    'Do NOT provide bank account details to unknown callers or messages',
    'Do NOT click on links asking for payment/bank details in SMS or WhatsApp',
    'Do NOT transfer money to "safe accounts" as told by unknown callers — this is a scam'
  ],
  benign: [
    'Be careful even with messages from unknown senders',
    'Never share personal information with strangers online',
    'Verify the sender before responding to any message',
    'When in doubt, do not click on any links',
    'Report suspicious messages to the relevant platform'
  ]
};

const LEGAL_REFERENCES = {
  phishing: {
    title: 'Phishing / Identity Theft',
    acts: [
      {
        name: 'Indian Penal Code',
        sections: [
          { code: 'IPC 419', description: 'Punishment for cheating by personation — imprisonment up to 3 years, fine' },
          { code: 'IPC 420', description: 'Cheating and dishonestly inducing delivery of property — imprisonment up to 7 years, fine' },
          { code: 'IPC 468', description: 'Cheating by false name/description (forgery for purpose of cheating) — 7 years' },
          { code: 'IPC 463', description: 'Making a false document or electronic record — up to 7 years' }
        ]
      },
      {
        name: 'Information Technology Act, 2000',
        sections: [
          { code: 'IT Act 66C', description: 'Identity theft — imprisonment up to 3 years, fine up to ₹5 lakhs' },
          { code: 'IT Act 66D', description: 'Cheating by impersonation using computer resources — up to 3 years, fine' },
          { code: 'IT Act 72', description: 'Breach of confidentiality and privacy — imprisonment up to 3 years, fine' }
        ]
      }
    ]
  },
  spam: {
    title: 'Spam / Unsolicited Communication',
    acts: [
      {
        name: 'Information Technology Act, 2000',
        sections: [
          { code: 'IT Act 66A', description: 'Sending offensive messages through communication services — up to 3 years, fine (Supreme Court struck down parts in 2015; check current law)' },
          { code: 'IT Act 72A', description: 'Body corporate causing disclosure of information without consent — up to 3 years, fine' }
        ]
      },
      {
        name: 'The Telecom Commercial Communications Customer Preference Regulations, 2018 (TRAI)',
        sections: [
          { code: 'TRAI Reg 2018', description: 'Customers can register for DND (Do Not Disturb) to reduce spam; violation is actionable under TRAI regulations' }
        ]
      }
    ]
  },
  malware: {
    title: 'Malware / Cyber Attack',
    acts: [
      {
        name: 'Information Technology Act, 2000',
        sections: [
          { code: 'IT Act 43', description: 'Penalty for damage to computer system — liable to pay damages up to ₹1 crore' },
          { code: 'IT Act 43A', description: 'Failure to protect data — compensation for failure to protect personal data' },
          { code: 'IT Act 66', description: 'Computer-related offences — imprisonment up to 3 years, fine' },
          { code: 'IT Act 66B', description: 'Punishment for dishonestly receiving criminal property — up to 7 years, fine' },
          { code: 'IT Act 66F', description: 'Cyber terrorism — imprisonment for life (for attack on critical infrastructure)' }
        ]
      }
    ]
  },
  financialTheft: {
    title: 'Financial Fraud / OTP Scam / Bank Details Theft',
    acts: [
      {
        name: 'Indian Penal Code',
        sections: [
          { code: 'IPC 419', description: 'Cheating by personation — imprisonment up to 3 years, fine' },
          { code: 'IPC 420', description: 'Cheating and dishonestly inducing delivery of property — imprisonment up to 7 years, fine' },
          { code: 'IPC 421', description: 'Dishonest or fraudulent removal of property to prevent distribution to creditors — up to 2 years, fine' },
          { code: 'IPC 422', description: 'Criminal breach of trust — imprisonment up to 3 years, fine' },
          { code: 'IPC 423', description: 'Criminal breach of trust by false representation — up to 3 years, fine' },
          { code: 'IPC 424', description: 'Criminal breach of trust by misappropriation — up to 3 years, fine' }
        ]
      },
      {
        name: 'Information Technology Act, 2000',
        sections: [
          { code: 'IT Act 66C', description: 'Identity theft — imprisonment up to 3 years, fine up to ₹5 lakhs' },
          { code: 'IT Act 66D', description: 'Cheating by impersonation using computer resources — up to 3 years, fine' },
          { code: 'IT Act 66B', description: 'Punishment for dishonestly receiving stolen property — up to 7 years, fine' }
        ]
      },
      {
        name: 'Reserve Bank of India Act, 1934',
        sections: [
          { code: 'RBI Act 30B', description: 'Unauthorised access to bank accounts — penalties may apply based on RBI regulations' }
        ]
      },
      {
        name: 'Prevention of Money Laundering Act, 2002',
        sections: [
          { code: 'PMLA 3', description: 'Offence of money laundering — imprisonment for 3-7 years, fine' }
        ]
      }
    ]
  },
  scam: {
    title: 'Online Scam / Cheating',
    acts: [
      {
        name: 'Indian Penal Code',
        sections: [
          { code: 'IPC 420', description: 'Cheating and dishonestly inducing delivery of property — up to 7 years, fine' },
          { code: 'IPC 406', description: 'Criminal breach of trust — up to 7 years' },
          { code: 'IPC 308', description: 'Attempt to commit culpable homicide — depending on severity' },
          { code: 'IPC 506', description: 'Criminal intimidation — up to 2 years / 7 years if oath or symptom used' }
        ]
      },
      {
        name: 'Information Technology Act, 2000',
        sections: [
          { code: 'IT Act 66D', description: 'Cheating by impersonation using computer resources — up to 3 years, fine' },
          { code: 'IT Act 66B', description: 'Punishment for dishonestly receiving criminal property — up to 7 years, fine' }
        ]
      }
    ]
  },
  harassment: {
    title: 'Harassment / Criminal Intimidation',
    acts: [
      {
        name: 'Indian Penal Code',
        sections: [
          { code: 'IPC 503', description: 'Criminal intimidation — anyone who threatens injury to person, reputation, or property — up to 2 years / 7 years with oath' },
          { code: 'IPC 506', description: 'Punishment for criminal intimidation — up to 2 years, fine' },
          { code: 'IPC 507', description: 'Criminal intimidation by anonymous communication — up to 2 years' },
          { code: 'IPC 354A', description: 'Sexual harassment — non-consensual explicit messages/pornography' },
          { code: 'IPC 509', description: 'Word/gesture intended to insult the modesty of a woman' },
          { code: 'IPC 228A', description: 'Disclosing identity of victim of sexual assault' }
        ]
      },
      {
        name: 'Information Technology Act, 2000',
        sections: [
          { code: 'IT Act 66E', description: 'Punishment for publishing/transmitting obscene material — imprisonment up to 3 years, fine' },
          { code: 'IT Act 67', description: 'Punishment for publishing/transmitting obscene material in electronic form — up to 5 years, fine up to ₹10 lakhs (first offence)' },
          { code: 'IT Act 66A', description: 'Offensive messages through communication services (partially struck down — check scope)' },
          { code: 'IT Act 72A', description: 'Disclosure of personal information causing harassment — up to 3 years, fine' }
        ]
      },
      {
        name: 'The Cinematograph Act / IT Rules 2021',
        sections: [
          { code: 'IT Rules 2021', description: 'Under IT Rules, social media intermediaries must remove content that is harassing within 24 hours of complaint' }
        ]
      }
    ]
  },
  socialEngineering: {
    title: 'Social Engineering / Tech Support Scam',
    acts: [
      {
        name: 'Indian Penal Code',
        sections: [
          { code: 'IPC 419', description: 'Cheating by personation — up to 3 years, fine' },
          { code: 'IPC 420', description: 'Cheating and dishonestly inducing delivery of property — up to 7 years, fine' },
          { code: 'IPC 463', description: 'Making false electronic record — up to 7 years' }
        ]
      },
      {
        name: 'Information Technology Act, 2000',
        sections: [
          { code: 'IT Act 66D', description: 'Cheating by impersonation using computer resources — up to 3 years, fine' },
          { code: 'IT Act 66B', description: 'Receiving criminal property — up to 7 years' },
          { code: 'IT Act 43', description: 'Damage to computer system through unauthorized access — penalty payable' }
        ]
      }
    ]
  },
  fraud: {
    title: 'Fraud / Deception',
    acts: [
      {
        name: 'Indian Penal Code',
        sections: [
          { code: 'IPC 415', description: 'Cheating — definition of cheating as dishonestly inducing a person to deliver property' },
          { code: 'IPC 420', description: 'Cheating and dishonestly inducing delivery — up to 7 years, fine' },
          { code: 'IPC 463', description: 'Forgery of electronic record — up to 7 years' },
          { code: 'IPC 465', description: 'Punishment for fraud — up to 2 years, fine' },
          { code: 'IPC 468', description: 'Forgery for purpose of cheating — up to 7 years' }
        ]
      },
      {
        name: 'Information Technology Act, 2000',
        sections: [
          { code: 'IT Act 66D', description: 'Cheating by personation using computers — up to 3 years, fine' },
          { code: 'IT Act 66B', description: 'Receiving stolen criminal property — up to 7 years, fine' }
        ]
      }
    ]
  },
  misinformation: {
    title: 'Misinformation / Fake News',
    acts: [
      {
        name: 'Indian Penal Code',
        sections: [
          { code: 'IPC 153A', description: 'Promoting enmity between groups on grounds of religion, race, etc. — up to 3 years' },
          { code: 'IPC 153B', description: 'Imputations and assertions prejudicial to national integration — up to 3 years' },
          { code: 'IPC 505', description: 'Statements creating or promoting enmity, hatred, or ill-will between classes — up to 3 years / 5 years' },
          { code: 'IPC 120B', description: 'Criminal conspiracy — depending on the offence conspired to' }
        ]
      },
      {
        name: 'Information Technology Act, 2000',
        sections: [
          { code: 'IT Act 66A', description: 'Sending offensive messages (partially struck down — check scope with legal counsel)' },
          { code: 'IT Act 69', description: 'Power to issue directions for interception, blocking in interest of sovereignty — applies to platforms' },
          { code: 'IT Act 79', description: 'Safe harbour provision — platforms must remove prohibited content upon notice' }
        ]
      },
      {
        name: 'IT Rules 2021 (Information Technology Rules)',
        sections: [
          { code: 'IT Rules 2021', description: 'Significant social media intermediaries must have grievance redressal mechanisms; false information causing public disorder is actionable' }
        ]
      }
    ]
  }
};

function analyzeMessage(message, messageType) {
    // Spell check function to correct common misspellings
    function correctSpelling(text) {
      const corrections = {
        // Common misspellings for threat-related terms
        'phising': 'phishing',
        'phisingg': 'phishing',
        'phisinggg': 'phishing',
        'otpp': 'otp',
        'otppp': 'otp',
        'verifcation': 'verification',
        'verificaton': 'verification',
        'verificaiton': 'verification',
        'suspend': 'suspended',
        'suspendedd': 'suspended',
        'suspendded': 'suspended',
        'verify': 'verify',
        'verifiy': 'verify',
        'verfiy': 'verify',
        'accunt': 'account',
        'accout': 'account',
        'acount': 'account',
        'passwrod': 'password',
        'pasword': 'password',
        'passowrd': 'password',
        'bankk': 'bank',
        'banck': 'bank',
        'bnak': 'bank',
        'bnk': 'bank',
        'bankkk': 'bank',
        'bancc': 'bank',
        'bannk': 'bank',
        'crad': 'card',
        'crads': 'card',
        'cad': 'card',
        'iddentitiy': 'identity',
        'identitiy': 'identity',
        'identty': 'identity',
        'frad': 'fraud',
        'fradud': 'fraud',
        'frudu': 'fraud',
        'scamm': 'scam',
        'scamn': 'scam',
        'scma': 'scam',
        'malwere': 'malware',
        'malwar': 'malware',
        'virusss': 'virus',
        'virussss': 'virus',
        'viruss': 'virus',
        'toxcity': 'toxicity',
        'toxcityy': 'toxicity',
        'toxcityyy': 'toxicity',
        'messgae': 'message',
        'messge': 'message',
        'mesage': 'message',
        'websit': 'website',
        'websitte': 'website',
        'websitteee': 'website',
        'calll': 'call',
        'cal': 'call',
        'caall': 'call',
        'emaail': 'email',
        'emial': 'email',
        'emai': 'email',
        'numver': 'number',
        'nummbber': 'number',
        'numer': 'number',
        'adress': 'address',
        'adres': 'address',
        'addres': 'address',
        'detalis': 'details',
        'detial': 'details',
        'detials': 'details',
        'informaion': 'information',
        'informaton': 'information',
        'informtion': 'information',
        'respnd': 'respond',
        'resond': 'respond',
        'responed': 'respond',
        'clik': 'click',
        'clikc': 'click',
        'clck': 'click',
        'linlk': 'link',
        'linnk': 'link',
        'linlk': 'link',
        'uppldate': 'update',
        'upadte': 'update',
        'updaet': 'update',
        'securirty': 'security',
        'securtiy': 'security',
        'securiry': 'security',
        'alertr': 'alert',
        'alart': 'alert',
        'alrt': 'alert',
        'warnging': 'warning',
        'warnig': 'warning',
        'warnng': 'warning',
        'suspicous': 'suspicious',
        'suspicoius': 'suspicious',
        'suspcioius': 'suspicious',
        'legitmate': 'legitimate',
        'legitamte': 'legitimate',
        'legtimate': 'legitimate',
        'authetic': 'authentic',
        'authantic': 'authentic',
        'authentc': 'authentic',
        'informaiton': 'information',
        'informaitoon': 'information',
        'identification': 'identification',
        'identifcation': 'identification',
        'identficaton': 'identification',
        'authentiaction': 'authentication',
        'authenticaion': 'authentication',
        'authenticaon': 'authentication',
        'scurity': 'security',
        'securit': 'security',
        'securitie': 'security',
        'viryus': 'virus',
        'vyrsus': 'virus',
        'vruss': 'virus',
        'malwere': 'malware',
        'malawre': 'malware',
        'malaw ware': 'malware',
        'phsihing': 'phishing',
        'phshing': 'phishing',
        'phsihng': 'phishing',
        'fradulent': 'fraudulent',
        'fradulant': 'fraudulent',
        'frudulet': 'fraudulent',
        'scamers': 'scammers',
        'scamerz': 'scammers',
        'scammerz': 'scammers',
        'haxors': 'hackers',
        'haxerz': 'hackers',
        'hackerz': 'hackers',
        'virusscan': 'virus scan',
        'virusscann': 'virus scan',
        'virusscane': 'virus scan'
      };
      
      // Apply corrections
      let correctedText = text;
      for (const [wrong, right] of Object.entries(corrections)) {
        const regex = new RegExp(`\\b${wrong}\\b`, 'g');
        correctedText = correctedText.replace(regex, right);
      }
      
      return correctedText;
    }
    
    // Apply spell checking to the message
    const correctedMessage = correctSpelling(message);
    const lowerMsg = correctedMessage.toLowerCase();
    const words = lowerMsg.split(/\s+/);
    const results = {
      riskLevel: 'very low',
      riskPercent: 0,
      toxicityLevel: 0,
      toxicityConfidence: 0,
      threats: [],
      whatNotToDo: [],
      protectYourself: [],
      legalReferences: [],
      messageType,
      matchedKeywords: [],
      confidence: 0
    };

  let totalScore = 0;
  let threatCount = 0;

  for (const [threatType, pattern] of Object.entries(THREAT_PATTERNS)) {
    let matchCount = 0;
    const matchedKW = [];

    for (const kw of pattern.keywords) {
      if (lowerMsg.includes(kw)) {
        matchCount++;
        matchedKW.push(kw);
      }
    }

    let emailSpecificMatch = 0;
    if (messageType === 'email' && pattern.emailSpecific) {
      for (const es of pattern.emailSpecific) {
        if (lowerMsg.includes(es)) {
          emailSpecificMatch++;
          matchedKW.push(es);
        }
      }
    }

    if (matchCount > 0 || emailSpecificMatch > 0) {
      const typeScore = (matchCount * pattern.weight) + (emailSpecificMatch * pattern.weight * 0.5);
      totalScore += typeScore;
      threatCount++;
      results.threats.push(threatType);
      results.matchedKeywords.push(...matchedKW);
    }
  }

  let maxToxicity = 0;
  let toxicityMatches = 0;
  for (const [tier, data] of Object.entries(TOXICITY_DICT)) {
    for (const word of data.words) {
      if (lowerMsg.includes(word)) {
        maxToxicity = Math.max(maxToxicity, data.score);
        toxicityMatches++;
      }
    }
  }
  results.toxicityLevel = maxToxicity;
  results.toxicityConfidence = Math.min(100, toxicityMatches * 20 + 30);

  const lengthFactor = Math.min(1, message.length / 50);
  const rawRisk = (totalScore * lengthFactor * 2) + (maxToxicity * 0.3);
  results.riskPercent = Math.min(100, Math.round(rawRisk));

  if (results.riskPercent <= 15) results.riskLevel = 'very low';
  else if (results.riskPercent <= 30) results.riskLevel = 'low';
  else if (results.riskPercent <= 50) results.riskLevel = 'medium';
  else if (results.riskPercent <= 75) results.riskLevel = 'high';
  else results.riskLevel = 'very high';

  if (results.threats.includes('financialTheft')) {
    results.riskLevel = 'very high';
    results.riskPercent = Math.max(results.riskPercent, 85);
  } else if (results.threats.includes('phishing') && (results.matchedKeywords.some(k => k.includes('otp')) || results.matchedKeywords.some(k => k.includes('password')) || results.matchedKeywords.some(k => k.includes('card')))) {
    results.riskLevel = 'high';
    results.riskPercent = Math.max(results.riskPercent, 70);
  } else if (results.threats.includes('phishing') && (results.matchedKeywords.some(k => k.includes('name')) || results.matchedKeywords.some(k => k.includes('age')) || results.matchedKeywords.some(k => k.includes('address')) || results.matchedKeywords.some(k => k.includes('email')) || results.matchedKeywords.some(k => k.includes('phone')) || results.matchedKeywords.some(k => k.includes('personal')) || results.matchedKeywords.some(k => k.includes('details')) || results.matchedKeywords.some(k => k.includes('information')) || results.matchedKeywords.some(k => k.includes('dob')) || results.matchedKeywords.some(k => k.includes('birthday')))) {
    results.riskLevel = 'medium';
    results.riskPercent = Math.max(results.riskPercent, 35);
  }

  if (results.threats.length === 0) {
    results.threats = ['benign'];
    results.riskLevel = 'very low';
    results.riskPercent = Math.min(10, results.riskPercent);
    results.riskPercent = results.riskPercent === 0 ? 0 : results.riskPercent;
  }

  results.whatNotToDo = [
    'Be careful even with messages from unknown senders',
    'Never share personal information with strangers online',
    'Verify the sender before responding to any message',
    'When in doubt, do not click on any links',
    'Report suspicious messages to the relevant platform'
  ];
  results.protectYourself = [
    'Always verify the sender before clicking any links',
    'Keep your personal information private online',
    'Use official apps/websites for transactions',
    'Enable two-factor authentication where possible',
    'Regularly review your account statements'
  ];

  const uniqueThreats = [...new Set(results.threats)];
  for (const threat of uniqueThreats) {
    if (WHAT_NOT_TO_DO[threat]) results.whatNotToDo = [...WHAT_NOT_TO_DO[threat]];
    if (PROTECTION_TIPS[threat]) results.protectYourself = [...PROTECTION_TIPS[threat]];
    if (LEGAL_REFERENCES[threat]) results.legalReferences.push(LEGAL_REFERENCES[threat]);
  }

  results.whatNotToDo = [...new Set(results.whatNotToDo)].slice(0, 5);
  results.protectYourself = [...new Set(results.protectYourself)].slice(0, 5);
  results.matchedKeywords = [...new Set(results.matchedKeywords)].slice(0, 10);

  const indicatorCount = results.threats.filter(t => t !== 'benign').length;
  const keywordDensity = results.matchedKeywords.length / Math.max(1, words.length);
  results.confidence = Math.min(100, Math.round(
    (indicatorCount * 20) + (keywordDensity * 1000) + (maxToxicity * 0.2) + 40
  ));

  return results;
}

function getEthicalAnalysis(threats, riskLevel, toxicityLevel, messageType) {
  const analysis = {
    summary: '',
    ethicalViolation: '',
    realWorldImpact: '',
    fairness: '',
    accountability: '',
    transparency: ''
  };

  const threat = threats[0] || 'benign';

  const summaries = {
    phishing: `The message demonstrates a classic phishing attack — attempting to trick the recipient into revealing sensitive personal or financial information by creating a false sense of urgency.`,
    spam: `This message appears to be unsolicited spam — attempting to promote fraudulent schemes or distribute harmful content to a large audience without consent.`,
    malware: `This message contains indicators of malware distribution — attempting to trick the recipient into downloading malicious software that could compromise their system and data.`,
    scam: `This message appears to be a financial scam — attempting to defraud the recipient through false promises of money, prizes, or investment returns.`,
    harassment: `This message contains harassing and threatening language — attempting to intimidate, demean, or cause emotional harm to the recipient.`,
    socialEngineering: `This message demonstrates social engineering tactics — attempting to manipulate the recipient into taking actions that compromise their own security.`,
    fraud: `This message shows signs of fraudulent intent — attempting to deceive the recipient through false pretenses or impersonation.`,
    misinformation: `This message may contain false or misleading information — attempting to manipulate public opinion or cause panic through unverified claims.`,
    financialTheft: `This is an attempt to steal financial information such as OTP, bank details, card details, or UPI credentials — the most common and dangerous cyber crime in India.`,
    benign: `This message does not show significant signs of malicious intent. However, always exercise caution with unknown messages.`
  };

  const violations = {
    phishing: `This violates principles of Honesty and Autonomy — the attacker deceives the victim into actions they would not otherwise take, denying their right to make informed decisions.`,
    spam: `This violates the principle of Consent — mass unsolicited communication is sent without the recipients' permission, violating their right to privacy and autonomy.`,
    malware: `This violates the principle of Non-Maleficence — the attacker intentionally causes harm to the victim's digital property and potentially their data and privacy.`,
    scam: `This violates the principle of Justice and Honesty — the scammer gains unfairly through deception, cheating the victim out of money or property.`,
    harassment: `This violates the principle of Non-Maleficence — causing emotional and psychological harm to the victim violates their right to safety and dignity.`,
    socialEngineering: `This violates the principle of Autonomy and Honesty — manipulating someone into compromising their own security is a violation of informed consent.`,
    fraud: `This violates the principles of Honesty and Justice — deliberate deception for unfair gain harms both the individual victim and society's trust in digital systems.`,
    misinformation: `This violates the principle of Truth and Transparency — spreading false information for manipulation undermines public trust and informed decision-making.`,
    financialTheft: `This violates the principles of Autonomy and Justice — the attacker attempts to gain unauthorized access to the victim's financial resources, stealing money through deception.`,
    benign: `No significant ethical violation detected, but general digital hygiene practices should always be followed.`
  };

  const impacts = {
    phishing: `Phishing attacks can lead to identity theft, financial loss, unauthorized access to personal accounts, and compromise of sensitive organizational data. In India, victims have lost lakhs of rupees to phishing scams targeting bank customers.`,
    spam: `Spam messages waste resources, spread scams and malware, erode trust in digital communication, and can be used to harvest email addresses for further attacks.`,
    malware: `Malware can steal personal data, encrypt files for ransom, hijack devices for botnets, spy on users, and cause significant financial and emotional distress. Ransomware attacks have cost Indian organizations crores of rupees.`,
    scam: `Scam victims can lose lakhs of rupees in financial scams. Beyond monetary loss, victims suffer psychological trauma, loss of trust, and in extreme cases, can be radicalised or exploited further.`,
    harassment: `Online harassment causes severe psychological harm including anxiety, depression, and in extreme cases, leads to self-harm or suicide. Targets of harassment often feel unsafe in digital spaces.`,
    socialEngineering: `Social engineering bypasses even strong technical security by targeting human psychology. Victims can lose financial data, intellectual property, or become accomplices in larger crimes without their knowledge.`,
    fraud: `Digital fraud costs India thousands of crores annually. Beyond individual financial loss, it erodes trust in online services, damages the digital economy, and disproportionately affects vulnerable populations.`,
    misinformation: `Fake news and misinformation can trigger real-world violence, disrupt public health efforts, influence elections, and cause panic. During events like COVID-19, misinformation has directly led to deaths and injuries.`,
    financialTheft: `OTP and bank detail scams are the #1 cyber crime in India. Victims have lost their entire bank savings in minutes. In 2023 alone, Indians lost over ₹1,000 crores to OTP/money-mule scams. Scammers drain bank accounts, take loans in the victim's name, and sell personal data on the dark web.`,
    benign: `While this message appears benign, continuous vigilance is essential as threats constantly evolve.`
  };

  const fairness_text = `This message violates the principle of Fairness because it attempts to exploit information asymmetries — the sender manipulates the victim through asymmetric knowledge, denying them a fair opportunity to understand and respond to the situation truthfully. The victim is denied access to accurate information needed to make free and informed choices.`;

  const accountability_text = `In ethical data science and technology, accountability means that those who design, deploy, and misuse these systems must be held responsible for their actions. In India, this is addressed through the IT Act 2000 and IPC provisions. However, a significant challenge remains in tracing perpetrators, especially when attacks are launched from anonymous or international sources.`;

  const transparency_text = `This message violates Transparency because it deliberately obscures the true identity, intent, and origin of the communication. Ethical data systems require transparency about who is communicating, what the purpose is, and where information originates. The deceptive nature of such messages makes it impossible for the recipient to exercise informed consent.`;

  analysis.summary = summaries[threat] || summaries.benign;
  analysis.ethicalViolation = violations[threat] || violations.benign;
  analysis.realWorldImpact = impacts[threat] || impacts.benign;
  analysis.fairness = fairness_text;
  analysis.accountability = accountability_text;
  analysis.transparency = transparency_text;

  return analysis;
}

// History functionality
let analysisHistory = [];

// Save analysis to history
function saveToHistory(analysis) {
    const historyItem = {
        id: Date.now(),
        timestamp: new Date().toLocaleString(),
        message: analysis.inputMessage.substring(0, 50) + (analysis.inputMessage.length > 50 ? '...' : ''),
        fullMessage: analysis.inputMessage,
        riskLevel: analysis.riskLevel,
        riskPercent: analysis.riskPercent,
        threats: analysis.threats
    };
    
    analysisHistory.unshift(historyItem); // Add to beginning
    
    // Keep only last 50 items
    if (analysisHistory.length > 50) {
        analysisHistory = analysisHistory.slice(0, 50);
    }
    
    updateHistoryDisplay();
}

// Update history count display
function updateHistoryDisplay() {
    const historyCount = document.getElementById('historyCount');
    if (!historyCount) return;
    
    historyCount.textContent = analysisHistory.length;
}

// Clear history
function clearHistory() {
    analysisHistory = [];
    updateHistoryDisplay();
}

// Wrapper for HTML call
function analyzeMessageJS(message, type) {
    const result = analyzeMessage(message, type || 'email');
    
    // Add input message to result for history
    result.inputMessage = message;
    
    // Save to history
    saveToHistory(result);
    
    return result;
}