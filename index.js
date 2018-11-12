var express = require('express');
var ParseServer = require('parse-server').ParseServer;
var path = require('path');
var ParseDashboard = require('parse-dashboard');
var SimpleSendGridAdapter = require('parse-server-sendgrid-adapter');

var databaseUri = process.env.DATABASE_URI || process.env.MONGODB_URI;

if (!databaseUri) {
  console.log('DATABASE_URI not specified, falling back to localhost.');
}

var serverUrl = process.env.SERVER_URL || 'http://localhost:1337/parse';

var serverConfig = {
  databaseURI: databaseUri || 'mongodb://localhost:27017/dev',
  cloud: process.env.CLOUD_CODE_MAIN || __dirname + '/cloud/main.js',
  appId: process.env.APP_ID || 'myAppId',
  masterKey: process.env.MASTER_KEY || '123',
  serverURL: serverUrl,

  //password reset
  emailAdapter: SimpleSendGridAdapter({
    apiKey: process.env.SENDGRID_API_KEY || '',
    fromAddress: 'reset@bloomlibrary.org',
  }),
  publicServerURL: process.env.publicServerURL || 'http://localhost:1337/parse', // apparently used by password reset emailer
  verifyUserEmails:true,
  appName: process.env.APP_NAME || 'BloomLibrary.org',

  //See IMPORTANT comment in public/choose-password.html
  customPages: {
      choosePassword: getChoosePasswordUrl(serverUrl) || 'http://localhost:1337/choose-password'
  }
};
var api = new ParseServer(serverConfig);
// Client-keys like the javascript key or the .NET key are not necessary with parse-server
// If you wish you require them, you can set them as options in the initialization above:
// javascriptKey, restAPIKey, dotNetKey, clientKey

// Because we are running this on Azure, for some reason, it cannot determine the connection is secure even if it is.
// I tried setting trustProxy to true instead, but that still didn't work.
// Setting this to true mirrors the way it is handled in https://github.com/Azure/parse-server-example (as of 12/7/16).
var allowInsecureHTTP = true;
var dashboard = new ParseDashboard({
    apps: [
        {
        appId: serverConfig.appId,
        serverURL: serverConfig.serverURL,
        masterKey: serverConfig.masterKey,
        appName: serverConfig.appName,
        production: serverConfig.serverURL.includes('production')
        }
    ],
    users: [
        {
        user: serverConfig.appId,
        pass: serverConfig.masterKey
        }
    ]
}, allowInsecureHTTP);

var app = express();

// Serve the Parse API on the /parse URL prefix
var mountPath = process.env.PARSE_MOUNT || '/parse';
app.use(mountPath, api);

app.get('/choose-password', function(req, res) {
    res.sendFile(path.join(__dirname, '/public/choose-password.html'));
})

app.use('/dashboard', dashboard);

var port = process.env.PORT || 1337;
var httpServer = require('http').createServer(app);
httpServer.listen(port, function() {
    console.log('bloom-parse-server running on port ' + port + '.');
});

function getChoosePasswordUrl(serverUrl) {
    var idx = serverUrl.indexOf('/parse');
    if (idx >= 0)
        return serverUrl.substring(0, idx) + '/choose-password';
    return serverUrl;
}