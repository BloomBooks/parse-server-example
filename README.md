# bloom-parse-server

This is the database backend for bloom-library.org, using the [parse-server](https://github.com/ParsePlatform/parse-server) module on Express.

Here is the full [Parse Server guide](https://github.com/ParsePlatform/parse-server/wiki/Parse-Server-Guide).

### Set Up For Local Development

1. Make sure you have at least Node 4.3.

    `node --version`
1. Clone this repo and go into its directory, and install or update the dependencies:

    `npm install`

1. Install mongodb server

1. Give mongodb a blank directory to work with, and run it:

    `c:\Program Files\MongoDB\Server\3.2\bin>mongod.exe --dbpath x:\temp\mongodata`

1. Start up this server:

    `npm start`

    Or, to debug, open bloom-parse-server in vscode, F5 (Debug: Launch via NPM). Note that this sets the masterid to "123", via an environment variable.

    To verify that it is running, open a browser to http://localhost:1337/test

1. Run Parse Dashboard:

    ```
    npm install parse-dashboard --global
    parse-dashboard --appId myAppId --masterKey "123" --serverURL
    ```

    This will say it is available at http://0.0.0.0, but actually it is at http://localhost.

1. Setup or update the mongodb Schema

    ```
    curl -X POST -H "X-Parse-Application-Id: myAppId" -H "X-Parse-Master-Key: 123" -d "{}" http://localhost:1337/parse/functions/setupTables
    ```
    You should get

    `{"result":"SetupTables ran to completion."}`

    and see the tables in the dashboard.


### Cloud Code

Normally you will only touch the "cloud code", found in cloud/main.js.

### Sample Queries

```
curl -X POST \
  -H "X-Parse-Application-Id: myAppId" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://localhost:1337/parse/functions/hello
```
