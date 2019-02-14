const AUTH_URL = '/login'
const REDIRECT_URL = '/redirect_url'

const NOW = !!process.env['NOW_REGION']


const session = require('express-session')
const mongosession = require('connect-mongodb-session')(session)

const app = require('express')()

app.use(require('cookie-parser')())
app.use(require('body-parser').urlencoded({ extended: true }))

const store = new mongosession({
  uri: require('@techspeakers/mongoclient').connectionUrl(),
  databaseName: 'moztechspeakers',
  collection: 'auth-session'
})

app.use(session({
  secret: process.env['AUTH_CLIENT_ID'],
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 1 day
    secure: true
  },
  store,
  resave: true,
  saveUninitialized: true,
}))


const Auth0Strategy = require('passport-auth0'),
      passport = require('passport')

passport.use(new Auth0Strategy({
    domain:       process.env['AUTH_DOMAIN'],
    clientID:     process.env['AUTH_CLIENT_ID'],
    clientSecret: process.env['AUTH_CLIENT_SECRET'],
    callbackURL:  REDIRECT_URL,
    proxy: true, // for missing https:// in callback url -- via:
    // https://github.com/strongloop/loopback-component-passport/issues/120#issuecomment-287373883
    scope: 'openid email profile',
  },
  (accessToken, refreshToken, extraParams, profile, done) => done(null, profile)
))

passport.serializeUser(function(user, done) {
  const claimGroups = user._json['https://sso.mozilla.com/claim/groups']
  const { name, email, picture } = user._json

  const usertoken = {
    name, email, picture,
    is_ts: claimGroups.indexOf('mozilliansorg_ts') !== -1,
    is_staff: claimGroups.indexOf('mozilliansorg_techspeakers-staff') !== -1,
  }

  done(null, usertoken)
});

passport.deserializeUser(function(id, done) {
  done(null, id)
});


app.use(require('express').static(require('path').join(__dirname, 'www')))

app.use(passport.initialize())
app.use(passport.session())


app.get(REDIRECT_URL,
  passport.authenticate('auth0', { failureRedirect: '/login' }),
  function(req, res) {
    if (!req.user) {
      return res.redirect('/auth_error')
    }
    authenticated(req,res)
  }
)

app.get(AUTH_URL,
  storeReturnUrl,
  passport.authenticate('auth0', {}),
  function (req, res) {
    authenticated(req,res)
})

function storeReturnUrl(req,res,next) {
  if (req.query.return_url) {
    req.session.return_url = req.query.return_url
  }

  next()
}

// Successfully authenticated
function authenticated(req, res) {
  // If this was one of the subdomains, set a domain-wide user ID cookie &
  // redirect back to the originating domain
  res.cookie('tsauth', req.sessionID, {
    maxAge: 1000 * 60 * 60 * 8,
    secure: true,
    domain: 'tchspk.rs',
    httpOnly: false,
  })

  if (req.session.return_url) {
    const redirectUrl = req.session.return_url
    delete req.session.return_url
    return res.redirect(redirectUrl)
  }

  res.redirect('/ok')
}


// Session info
app.get('/info', (req, res) => {
  res.json(req.session||{})
})

// Fallback
app.get('*', (req, res) => res.send(
`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Mozilla TechSpeakers</title>
<style>
html, body { width: 100%; height: 100%; margin: 0 }
body { display: flex; justify-content: center; align-items: center;  background-color: #229ed4 }
svg { width: 60vw; max-width: 20rem; max-height: 60vh }
</style>
</head>
<body><svg xmlns="http://www.w3.org/2000/svg" aria-label="Mozilla TechSpeakers" aria-role="img" viewBox="0 0 176.17 162.55"><path d="M88.05 162.55a7.93 7.93 0 0 1-7.87-7.98V35.07c0-4.4 3.53-7.98 7.87-7.98a7.93 7.93 0 0 1 7.88 7.97v119.51c0 4.4-3.53 7.97-7.88 7.97m26.77-32.66a7.93 7.93 0 0 1-7.87-7.98V11.16c0-4.4 3.52-7.98 7.87-7.98a7.93 7.93 0 0 1 7.88 7.98V121.9c0 4.4-3.53 7.98-7.88 7.98" fill="#f5e260"></path><path d="M141.3 101.2a7.93 7.93 0 0 1-7.88-7.98V7.97c0-4.4 3.53-7.97 7.88-7.97a7.93 7.93 0 0 1 7.87 7.97v85.25c0 4.4-3.52 7.98-7.87 7.98m27-26.3a7.93 7.93 0 0 1-7.88-7.97V19.92c0-4.4 3.53-7.96 7.88-7.96a7.91 7.91 0 0 1 7.87 7.96v47.01c0 4.4-3.52 7.97-7.87 7.97" fill="#f9efad"></path><path d="M61.35 129.88a7.93 7.93 0 0 1-7.88-7.98V11.16c0-4.4 3.53-7.98 7.88-7.98a7.93 7.93 0 0 1 7.87 7.98V121.9c0 4.4-3.52 7.98-7.87 7.98" fill="#f2c616"></path><path d="M34.87 101.2A7.93 7.93 0 0 1 27 93.22V7.97C27 3.57 30.53 0 34.87 0a7.93 7.93 0 0 1 7.88 7.97v85.25c0 4.4-3.53 7.98-7.88 7.98m-27-26.3A7.93 7.93 0 0 1 0 66.93V19.92c0-4.4 3.53-7.96 7.87-7.96a7.92 7.92 0 0 1 7.88 7.96v47.01c0 4.4-3.53 7.97-7.88 7.97" fill="#f3901a"></path></svg></body>
</html>`
))


const listener = app.listen()

if (!NOW) {
  const port = listener && listener.address ? listener.address().port : ''
  console.log(`Server started${port?' on :'+port:''} ...`)
}
