/* 
 * What about serving up static content, kind of like apache? 
 * This time, you are required to present a user and password to the login route
 * before you can read any static content.
 */

var process = require('process');
// run ftd.js as 

// nodejs ftd.js PORT_NUMBER
var port = parseInt(process.argv[2]); 
var express = require('express');
var cookieParser = require('cookie-parser');

var app = express();
app.use(cookieParser()); // parse cookies before processing other middleware

const sqlite3 = require('sqlite3').verbose();

var bodyParser = require('body-parser');
app.use(bodyParser.json()); // support json encoded bodies
app.use(bodyParser.urlencoded({ extended: true })); // support encoded bodies
app.use(express.static('static-files')); 

var db = new sqlite3.Database('db/database.db', (err) => {
	if (err) {
		console.error(err.message);
	}
	console.log('Connected to the database.');
});

function arrayRemove(array, element){

	let index = array.indexOf(element);
	if(index!=-1) array.splice(index,1);
}


// ================================================================================
// ================================================================================
// ================================================================================

class MyErrors{
	constructor(msg = '', statusCode){
		this.message = `Error: ${msg}`;
		this.statusCode = statusCode;
	}
}

// some user-defined errors
class DatabaseError extends MyErrors{
	constructor(msg){super(msg, 500);}
}
class InputError extends MyErrors{
	constructor(msg){super(msg, 400);}
}
class NotFoundError extends MyErrors{
	constructor(msg){super(msg, 404);}
}
class BadAuthError extends MyErrors{
	constructor(msg){super(msg, 401);}
}
class ForbiddenError extends MyErrors{
	constructor(msg){super(msg, 403);}
}
class ConflictError extends MyErrors{
	constructor(msg){super(msg, 409);}
}
class BadWebSocketError extends MyErrors{
	constructor(msg){super(msg, null);}
}

/* throws DatabaseError */
async function queryAll(queryString, params = []){
	return new Promise((resolve, reject) => db.all(
		queryString, 
		params, 
		(err, rows) => (err) ? reject(new DatabaseError(err)) : resolve(Array.from(rows))
	));
}

/* throws DatabaseError */
async function queryRun(queryString, params = []){
	return new Promise((resolve, reject) => db.run(
		queryString, 
		params, 
		(err) => (err) ? reject(new DatabaseError(err)) : resolve() 
	));
} 

/* throws DatabaseError, NotFoundError */
async function queryGet(queryString, params = []){
	return new Promise((resolve, reject) => db.get(
		queryString,
		params, 
		(err, row) => {
			if (err){
				reject(new DatabaseError(err));
			} else if (row == null){
				reject(new NotFoundError(`${queryString} < ${params} not found.`));
				// potential security risk ^, don't let client see schema
			} else {
				resolve(row);
			}
		}
	));
}

// input sanitisation
isAlphaNumeric = (str) => RegExp("^[0-9a-zA-Z]+$").test(str);
isHex = (str) => RegExp("^[0-9a-fA-F]+$").test(str);

/* throws InputError, NotFoundError */
async function usernameExists(username){
	if (!isAlphaNumeric(username)){
		throw new InputError(`bad username: ${username}.`);
	}
	try {
		await queryGet(
			'SELECT username FROM user WHERE username =?;',
			[username]
		);
		return true;
	} catch (e){
		if (e instanceof NotFoundError){
			return false;
		} else {
			throw e;
		}
	}
}

/* throws InputError, NotFoundError, BadAuthError */
async function authenticate(username, passwordHash){
	if (!isAlphaNumeric(username)){
		throw new InputError(`bad username: '${username}'.`);
	}
	if (!isHex(passwordHash)){
		throw new InputError(`bad password hash: '${passwordHash}'.`);
	}
	let user = await queryGet(
		'SELECT passwordHash FROM user WHERE username =?;',
		[username]
	);

	if (user.passwordHash != passwordHash){
		throw new BadAuthError(
			`bad username/password combo: '${username}'/'${passwordHash}'.`
		);
	}
}

async function handleResponseErrors(e, res){
	if (e instanceof MyErrors){
		res.status(e.statusCode);
	} else {
		res.status(500);
	}
	res.send({error: e.message});
	console.log(e.message);
}


// ================================================================================
// ================================================================================
// ================================================================================
const EventEmitter = require('events');

/* throws BadWebSocket */
class WebSocketStuff {

	static getUsernamePassword(url){
		let usernamePasswordHash = url.match(/\/\?username=(.+)&passwordHash=(.+)/i);

		// check if username is defined
		if (usernamePasswordHash == null){
			throw new BadWebSocketError(
				'Someone attempted connection without username and password parameter.'
			);
		}
		return {
			username: usernamePasswordHash[1],
			passwordHash: usernamePasswordHash[2]
		}
	}

	static async auth(url, ws){
		try {
			var {username, passwordHash} = WebSocketStuff.getUsernamePassword(url);
		} catch (e) {
			ws.send('Format is "/?username=<name>&passwordHash=<pass>".');
			throw(e);
		}
		//check if username exists
		try {
			await authenticate(username, passwordHash);
		} catch (e) {
			let msg;
			if (e instanceof InputError){
				msg = `attempted connection with bad username/passwordHash string: '${username}'/'${passwordHash}'.`;
			} else if (e instanceof NotFoundError){
				msg = `attempted connection with unavailable username: '${username}'.`;
			} else if (e instanceof BadAuthError){
				msg = `attempted connection with invalid passwordHash: '${passwordHash}' for user: '${username}'.`;
			} else {
				throw e;
			}
			ws.send(msg);
			throw new BadWebSocketError('Someone ' + msg);
		}
	}
}

class WebSocketConnections extends EventEmitter{
	constructor(){
		super();
		this.connections = {};
	}

	addConnection(key, webSocket){
		let conn = this.connections[key];

		if (conn){
			conn.add(webSocket);
		} else {
			this.emit('connected', key);
			this.connections[key] = new WebSocketConnection(
				key,
				webSocket
			);
		}
	}

	removeConnection(key, webSocket){
		let conn = this.connections[key];

		conn.remove(webSocket);

		if (conn.isEmpty()){
			this.emit('disconnected', key);
			delete this.connections[key];
		}

	}

	do = (key, func) => this.connections[key].do(func);

	tryToDo(key, func){
		if (this.connections[key]){
			this.do(key, func);
		}
	}

	isConnected = (key) => this.connections[key] !== undefined;
}

class WebSocketConnection{
	constructor(key, initial = null){
		this.key = key;
		this.webSockets = (initial) ? [initial] : [];
	}

	add = (newWebSocket) => this.webSockets.push(newWebSocket);
	
	remove = (oldWebSocket) => arrayRemove(this.webSockets, oldWebSocket);

	isEmpty = () => (this.webSockets.length == 0);

	//do = (func) => this.webSockets.forEach(func);
	do = (func) => {
		for (let webSocket of this.webSockets){
			func(webSocket);
		}
	}
	
}

app.use('/',express.static('static_files')); // this directory has files to be returned

const messageConnections = new WebSocketConnections();
var messagePort = port + 1; 
var WebSocketServer = require('ws').Server;

// ================================================================================

const messageWebSocket = new WebSocketServer({port: messagePort});
messageWebSocket.on('connection', async function(ws, req) {
	
	try {
		await WebSocketStuff.auth(req.url, ws);
	} catch (e) {
		ws.close();
		if (e instanceof BadWebSocketError) {
			console.log(e.message);
			return;
		}
		throw e;
	}
	let {username, passwordHash} = WebSocketStuff.getUsernamePassword(req.url);

	ws.username = username;
	messageConnections.addConnection(username, ws);
	//messageConnectedUsers[username] = ws;

	ws.on('message', async (msgStr) => {
		let msg = JSON.parse(msgStr); // TODO: catch json parse error

		for (let expectedKey of ['sender', 'passwordHash', 'recipient', 'messageEncrypted', 'encryption_iv']){
			if (msg[expectedKey] == undefined){
				console.log(`Message: '${msg}' missing parameter '${expectedKey}'`);
				return;
			}
		}
		if (msg.sender != ws.username){
			console.log(`'${ws.username}' tried to send message with username: '${msg.sender}'.`);
			return;
		}
		try {
			await authenticate(msg.sender, msg.passwordHash);

			console.log('received message:', msg);
			await receiveMessage(
				msg.sender, 
				msg.recipient, 
				msg.messageEncrypted, 
				msg.encryption_iv
			);
		} catch (e) {
			ws.send(JSON.stringify({error: e.message}));
		}
	});
	ws.on('close', function(){
		console.log(`'${ws.username}' messages websocket disconnected.`)
		//messageConnectedUsers[ws.username] = undefined;
		messageConnections.removeConnection(username, ws);
	});
	console.log(`'${username}' message websocket connected.`);
});

var friendPort = port + 2; 
const friendConnections = new WebSocketConnections();
const friendWebSocket = new WebSocketServer({port: friendPort});

friendWebSocket.on('connection', async function(ws, req) {
	try {
		await WebSocketStuff.auth(req.url, ws);
	} catch (e) {
		ws.close();
		if (e instanceof BadWebSocketError) {
			console.log(e.message);
			return;
		}
		throw e;
	}
	let {username, passwordHash} = WebSocketStuff.getUsernamePassword(req.url);

	ws.username = username;
	friendConnections.addConnection(username, ws);

	ws.on('close', function(){
		console.log(`'${ws.username}' friend websocket disconnected.`)
		friendConnections.removeConnection(username, ws);
	});
	console.log(`'${username}' friends websocket connected.`);
});


var friendRequestPort = port + 3; 
const friendRequestConnections = new WebSocketConnections();
const friendRequestWebSocket = new WebSocketServer({port: friendRequestPort});

friendRequestWebSocket.on('connection', async function(ws, req) {
	try {
		await WebSocketStuff.auth(req.url, ws);
	} catch (e) {
		ws.close();
		if (e instanceof BadWebSocketError) {
			console.log(e.message);
			return;
		}
		throw e;
	}
	let {username, passwordHash} = WebSocketStuff.getUsernamePassword(req.url);

	ws.username = username;
	friendRequestConnections.addConnection(username, ws);

	let users; 
	try {
		users = await queryAll(
			`SELECT DISTINCT username, 
			friend1 IS NOT NULL as 'areFriends',
			requester IS NOT NULL AS 'hasFriendRequest', 
			username=requester AS 'isRequester'
			FROM user LEFT OUTER JOIN friendRequest
			ON username IN (requester, requestee)
			AND '${username}' IN (requester, requestee)
			LEFT OUTER JOIN friends
			ON username IN (friend1, friend2)
			AND '${username}' IN (friend1, friend2)
			WHERE '${username}'<>username;
			ORDER BY username`,
			[]
		);

	} catch (e) {
		if (e instanceof NotFoundError ||
			e instanceof InputError){
			users = [];
		} else {
			ws.send({error: e.message});
			return;
		}
	}

	for (let user of users){
		ws.send(JSON.stringify(user));
	}

	ws.on('message', async (msgStr) => {
		let msg = JSON.parse(msgStr);
		for (let expectedKey of ['sender', 'passwordHash', 'recipient']){
			if (msg[expectedKey] == undefined){
				console.log(`Message: '${msg}' missing parameter '${expectedKey}'`);
				return;
			}
		}
		if (msg.sender != ws.username){
			console.log(`'${ws.username}' tried to send message with username: '${msg.sender}'.`);
			return;
		}
		try {
			await authenticate(msg.sender, msg.passwordHash);

			await sendFriendRequest(
				msg.sender, 
				msg.recipient
			);
		} catch (e) {
			ws.send(JSON.stringify({error: e.message}));
			console.log(e.message);
		}
	});

	ws.on('close', function(){
		console.log(`'${ws.username}' friend request websocket disconnected.`)
		friendRequestConnections.removeConnection(username, ws);
	});
	console.log(`'${username}' friend request websocket connected.`);
});


var friendsOnlinePort = port + 4; 
const friendsOnlineConnections = new WebSocketConnections();
const friendsOnlineWebSocket = new WebSocketServer({port: friendsOnlinePort});

friendsOnlineWebSocket.on('connection', async function(ws, req) {
	try {
		await WebSocketStuff.auth(req.url, ws);
	} catch (e) { 
		ws.close();
		if (e instanceof BadWebSocketError) {
			console.log(e.message);
			return;
		}
		throw e;
	}
	let {username, passwordHash} = WebSocketStuff.getUsernamePassword(req.url);

	ws.username = username;
	friendsOnlineConnections.addConnection(username, ws);
	/*
	try {
		let friends = await(getFriends(username));
		for (let friend of friends){
			if (messageConnections.isConnected(friend.username)) {
				let message = JSON.stringify({
					username: friend.username,
					connected: true
				});
				ws.send(message);
			}
		}
	} catch (e) {
		console.log(e);
	}
	*/

	ws.on('close', function(){
		console.log(`'${ws.username}' friends online websocket disconnected.`)
		friendsOnlineConnections.removeConnection(username, ws);
	});
	console.log(`'${username}' friends online websocket connected.`);
});


messageConnections.on('connected', async (username) => {
	try {
		let message = JSON.stringify({
			username: username,
			connected: true
		});
		let friends = await(getFriends(username));
		for (let friend of friends){
			friendsOnlineConnections.tryToDo(
				friend.username,
				(ws) => ws.send(message)
			);
		}
	} catch (e) {
		console.log(e.message);
	}
});

messageConnections.on('disconnected', async (username) => {
	try {
		let message = JSON.stringify({
			username: username,
			connected: false
		});
		let friends = await(getFriends(username));
		for (let friend of friends){
			friendsOnlineConnections.tryToDo(
				friend.username,
				(ws) => ws.send(message)
			);
		}
	} catch (e) {
		console.log(e.message);
	}
});
// ================================================================================
// ================================================================================
// ================================================================================

getFriends = (username) => queryAll(
	`SELECT friend1 AS username
	FROM friends
	WHERE friend2 =?

	UNION

	SELECT friend2 AS username
	FROM friends 
	WHERE friend1 =?`,
	[username, username]
);

async function sendFriendRequest(sender, recipient){

	let username = sender,
		friend = recipient;

	await usernameExists(friend);

	let isFriendRequested;

	let areFriends, hasFriendRequest, isRequester;

	try {
		let friendRequests = await queryGet(
			'SELECT * FROM friendRequest WHERE requester=? AND requestee=?',
			[friend, username]
		);
		isFriendRequested = true;
	} catch (e){
		if (e instanceof NotFoundError){
			isFriendRequested = false;
		} else {
			throw e;
		}
	}
	
	if (isFriendRequested){
		// if the other user requested a friend request,
		// make them friends and delete the previous request
		await queryRun('BEGIN TRANSACTION');

		await queryRun(
			'INSERT INTO friends(friend1, friend2) VALUES (?, ?);',
			[username, friend]
		);

		await queryRun(
			`DELETE FROM friendRequest
			WHERE ? in (requester, requestee) 
			AND ? in (requester, requestee);`,
			[username, friend]
		);

		await queryRun('END TRANSACTION');

		addNewFriend(friend, username);
		addNewFriend(username, friend);


	} else {
		// otherwise, just add a friend request to friendRequests
		await queryRun(
			'INSERT INTO friendRequest(requester, requestee) VALUES (?, ?);',
			[username, friend]
		);
	}

	if (isFriendRequested){
		sendRequest(sender, recipient, true, false, false);
		sendRequest(recipient, sender, true, false, false);
	} else {
		sendRequest(sender, recipient, false, true, false);
		sendRequest(recipient, sender, false, true, true);		
	}
}

function sendRequest(username, friend, areFriends, hasFriendRequest, isRequester){
	let msg = {
		username: friend, 
		areFriends: areFriends,
		hasFriendRequest: hasFriendRequest,
		isRequester: isRequester
	}

	friendRequestConnections.tryToDo(
		username, 
		(ws)=>ws.send(JSON.stringify(msg))
	);
}

async function receiveMessage(sender, recipient, messageEncrypted, encryption_iv) {

	if (!isHex(messageEncrypted)) {
		throw new InputError(`bad message: '${messageEncrypted}'.`);
	} else if (!isHex(encryption_iv)) {
		throw new InputError(`bad iv: '${encryption_iv}'.`);
	}

	await checkFriends(sender, recipient);

	let timestamp = new Date().toISOString();

	await queryRun(
		`INSERT INTO message(
			sender, recipient, messageEncrypted, encryption_iv, timestamp
		) VALUES (?, ?, ?, ?, ?);`,
		[sender, recipient, messageEncrypted, encryption_iv, timestamp]
	);

	sendMessage(
		sender,
		recipient,
		messageEncrypted,
		encryption_iv,
		timestamp,
	);
}

function sendMessage(sender, recipient, messageEncrypted, encryption_iv, timestamp){
	msg = JSON.stringify({
		sender: sender,
		recipient: recipient,
		messageEncrypted: messageEncrypted,
		encryption_iv: encryption_iv,
		timestamp: timestamp,
		error: null
	});

	for (let username of [sender, recipient]){
		messageConnections.tryToDo(
			username, 
			(ws) => ws.send(msg)
		);
	}
}

async function addNewFriend(friendToAdd, friendToReceive){
	let userKey = await queryGet(
		`SELECT publicKey
		FROM userKeys
		WHERE username =?;`,
		[friendToAdd]
	);

	let msg = {
		friend: friendToAdd, 
		publicKey: userKey.publicKey,
		connected: messageConnections.isConnected(friendToAdd)
	}

	friendConnections.tryToDo(
		friendToReceive, 
		(ws)=>ws.send(JSON.stringify(msg))
	);
}



app.listen(port, function () {
  console.log('Example app listening on port '+port);
});



app.get('/login/:u/passwordHash/:p', async function(req, res) {

	let username = req.params.u,
		passwordHash = req.params.p;

	try {
		await authenticate(username, passwordHash);

		let user = await queryGet(
			`SELECT privateKeyEncrypted, encryption_iv
			FROM userKeys
			WHERE username =?;`,
			[username]
		);

		res.status(200);
		res.send(JSON.stringify(user));
	} catch (e) {
		handleResponseErrors(e, res);
	}
});

// register api
app.put('/register/:u\
/passwordHash/:p\
/publicKey/:publicKey\
/privateKeyEncrypted/:privateKey\
/encryption_iv/:iv', async function(req, res) {
	let username = req.params.u,
		passwordHash = req.params.p,
		privateKeyEncrypted = req.params.privateKey,
		encryption_iv = req.params.iv,
		publicKey = req.params.publicKey;

	try {
		if (await usernameExists(username)){
			throw new ConflictError(`username: '${username}' already taken.`);
		}

		let hexInputs = [
			passwordHash, 
			privateKeyEncrypted, 
			encryption_iv, 
			publicKey
		];

		for (let hexInput of hexInputs){
			if (!isHex(hexInput)) {
				throw new InputError(`bad hex string: '${hexInput}'.`);
			}
		}

		//TODO: check lengths of inputs

		// if userKeys insert fails, user insert should be rolled back too
		await queryRun('BEGIN TRANSACTION');

		await queryRun(
			'INSERT INTO user(username, passwordHash) VALUES (?, ?);',
			[username, passwordHash]
		);

		await queryRun(
			`INSERT INTO userKeys(
				username, publicKey, privateKeyEncrypted, encryption_iv
			) VALUES (?, ?, ?, ?);`,
			[username, publicKey, privateKeyEncrypted, encryption_iv]
		);

		await queryRun('END TRANSACTION');

		let users = await queryAll(`
			SELECT username 
			FROM user 
			WHERE username<>?;`,
			[username]
		);
		for (let user of users){
			sendRequest(user.username, username, false, false, false);
		}

		res.status(200);
		res.send({});

	} catch (e) {
		handleResponseErrors(e, res);
		return;
	}
});

app.post('/sendFriendRequest/:u/passwordHash/:p/friend/:f', async function(req, res) {

	let username = req.params.u,
		passwordHash = req.params.p,
		friend = req.params.f;

	try {
		await authenticate(username, passwordHash);
		await usernameExists(friend);

		let isFriendRequested;
		try {
			let friendRequests = await queryGet(
				'SELECT * FROM friendRequest WHERE requester=? AND requestee=?',
				[friend, username]
			);
			isFriendRequested = true;
		} catch (e){
			if (e instanceof NotFoundError){
				isFriendRequested = false;
			} else {
				throw e;
			}
		}
		
		if (isFriendRequested){
			// if the other user requested a friend request,
			// make them friends and delete the previous request
			await queryRun('BEGIN TRANSACTION');

			await queryRun(
				'INSERT INTO friends(friend1, friend2) VALUES (?, ?);',
				[username, friend]
			);

			await queryRun(
				`DELETE FROM friendRequest
				WHERE ? in (requester, requestee) 
				AND ? in (requester, requestee);`,
				[username, friend]
			);

			await queryRun('END TRANSACTION');

			addNewFriend(friend, username);
			addNewFriend(username, friend);

		} else {
			// otherwise, just add a friend request to friendRequests
			await queryRun(
				'INSERT INTO friendRequest(requester, requestee) VALUES (?, ?);',
				[username, friend]
			);
		}
		res.status(200);
		res.send({});
	} catch (e) {
		handleResponseErrors(e, res);
	}
});

app.get('/getFriends/:u/passwordHash/:p', async function(req,res){
	
	let username = req.params.u,
		passwordHash = req.params.p;

	try {
		await authenticate(username, passwordHash);

		let friends = await queryAll(
			`SELECT friend.username, publicKey
			FROM (
				SELECT friend1 AS username
				FROM friends
				WHERE friend2 =?

				UNION

				SELECT friend2 AS username
				FROM friends 
				WHERE friend1 =?
			) friend, userKeys
			WHERE friend.username = userKeys.username
			ORDER BY friend.username`,
			[username, username]
		);

		res.status(200);
		let friendsWithOnline = friends.map((friend)=>{
			friend.connected = messageConnections.isConnected(friend.username);
			return friend;
		});
		res.send(friendsWithOnline);
	} catch (e) {
		handleResponseErrors(e, res);
	}
});

app.get('/searchUsers/:u/passwordHash/:p/search/', async function(req,res){
	
	let username = req.params.u,
		passwordHash = req.params.p,
		users;

	try {
		await authenticate(username, passwordHash);

		try {

			users = await queryAll(
				`SELECT DISTINCT username, 
				friend1 IS NOT NULL as 'areFriends',
				requester IS NOT NULL AS 'hasFriendRequest', 
				username=requester AS 'isRequester'
				FROM user LEFT OUTER JOIN friendRequest
				ON username IN (requester, requestee)
				AND '${username}' IN (requester, requestee)
				LEFT OUTER JOIN friends
				ON username IN (friend1, friend2)
				AND '${username}' IN (friend1, friend2)
				WHERE '${username}'<>username;`,
				[]
			);

		} catch (e) {
			if (e instanceof NotFoundError ||
				e instanceof InputError){
				users = [];
			} else {
				throw e;
			}
		}

		res.status(200);
		res.send(users);

	} catch (e) {
		handleResponseErrors(e, res);
	}

});

app.get('/searchUsers/:u/passwordHash/:p/search/:search', async function(req,res){
	
	let username = req.params.u,
		passwordHash = req.params.p,
		search = req.params.search,
		users;

	try {
		await authenticate(username, passwordHash);

		try {
			if (!isAlphaNumeric(search)){
				throw InputError;
			}

			users = await queryAll(
				`SELECT DISTINCT username, 
				friend1 IS NOT NULL as 'areFriends',
				requester IS NOT NULL AS 'hasFriendRequest', 
				username=requester AS 'isRequester'
				FROM user LEFT OUTER JOIN friendRequest
				ON username IN (requester, requestee)
				AND (requester LIKE '${search}%' 
				OR requestee LIKE '${search}%')
				AND '${username}' IN (requester, requestee)
				LEFT OUTER JOIN friends
				ON username IN (friend1, friend2)
				AND '${username}' IN (friend1, friend2)
				WHERE username LIKE '${search}%'
				AND '${username}'<>username;`,
				[]
			);

		} catch (e) {
			if (e instanceof NotFoundError ||
				e instanceof InputError){
				users = [];
			} else {
				throw e;
			}
		}

		res.status(200);
		res.send(users);

	} catch (e) {
		handleResponseErrors(e, res);
	}

});

app.get('/getPublicKey/:u/passwordHash/:p/friend/:f', async function(req,res){
	
	let username = req.params.u,
		passwordHash = req.params.p,
		friend = req.params.f;

	try {
		await authenticate(username, passwordHash);
		await checkFriends(username, friend);

		let friendObj = await queryAll(
			`SELECT publicKey
			FROM userKeys
			WHERE username = ?;`,
			[friend]
		);

		res.status(200);
		res.send(JSON.stringify(friendObj));
	} catch (e) {
		handleResponseErrors(e, res);
	}
});

app.get('/getMessages/:u/passwordHash/:p/friend/:f', async function(req,res){
	
	let username = req.params.u,
		passwordHash = req.params.p,
		friend = req.params.f;

	try {
		await authenticate(username, passwordHash);

		checkFriends(username, friend);

		let messages = await queryAll(
			`SELECT *
			FROM message
			WHERE ? in (sender, recipient)
			AND ? in (sender, recipient)`,
			[username, friend]
		);

		res.status(200);
		res.send(messages);
	} catch (e) {
		handleResponseErrors(e, res);
	}
});

app.get('/getLastMessage/:u/passwordHash/:p/friend/:f', async function(req,res){
	
	let username = req.params.u,
		passwordHash = req.params.p,
		friend = req.params.f;

	try {
		await authenticate(username, passwordHash);

		checkFriends(username, friend);

		let message;
		try {
			message = await queryGet(
				`SELECT *
				FROM message
				WHERE ? in (sender, recipient)
				AND ? in (sender, recipient)
				ORDER BY timestamp DESC
				LIMIT 1;`,
				[username, friend]
			);
		} catch (e) {
			if (e instanceof NotFoundError){
				message = '';
			} else {
				throw e;
			}
		}

		res.status(200);
		res.send(message);
	} catch (e) {
		handleResponseErrors(e, res);
	}
});


async function checkFriends(username1, username2){
	if (username1 == username2) {
		throw new InputError('user cannot be friends with themselves.');
	}
	await usernameExists(username1);
	await usernameExists(username2);
	try {
		await queryGet(
			`SELECT * 
			FROM friends 
			WHERE ? IN (friend1,friend2) 
			AND ? IN (friend1, friend2)
			AND ? <> ?;`,
			[username1, username2, username1, username2]
		);
	} catch (e) {
		if (e instanceof NotFoundError){
			throw new ForbiddenError(`'${username1}' is not friends with '${username2}'`);
		} else {
			throw e;
		}
	}	
}


