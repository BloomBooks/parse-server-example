var express = require('express');
var ParseServer = require('parse-server').ParseServer;
var ParseDashboard = require('parse-dashboard');
var SimpleSendGridAdapter = require('parse-server-sendgrid-adapter');

var databaseUri = process.env.DATABASE_URI || process.env.MONGODB_URI;

if (!databaseUri) {
  console.log('DATABASE_URI not specified, falling back to localhost.');
}

var serverConfig = {
  databaseURI: databaseUri || 'mongodb://localhost:27017/dev',
  cloud: process.env.CLOUD_CODE_MAIN || __dirname + '/cloud/main.js',
  appId: process.env.APP_ID || 'myAppId',
  masterKey: process.env.MASTER_KEY || '',
  serverURL: process.env.SERVER_URL || 'http://localhost:1337/parse',

  //password reset
  emailAdapter: SimpleSendGridAdapter({
    apiKey: process.env.SENDGRID_API_KEY,
    fromAddress: 'reset@bloomlibrary.org',
  }),
  publicServerURL: process.env.SERVER_URL || 'http://localhost:1337/parse', // apparently used by password reset emailer
  verifyUserEmails:true,
  appName: process.env.APP_NAME || 'BloomLibrary.org'
};
var api = new ParseServer(serverConfig);
// Client-keys like the javascript key or the .NET key are not necessary with parse-server
// If you wish you require them, you can set them as options in the initialization above:
// javascriptKey, restAPIKey, dotNetKey, clientKey

var allowInsecureHTTP = false;
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

app.use('/dashboard', dashboard);

var port = process.env.PORT || 1337;
var httpServer = require('http').createServer(app);
httpServer.listen(port, function() {
    console.log('bloom-parse-server running on port ' + port + '.');
});
