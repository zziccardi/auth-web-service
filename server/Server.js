
const fs = require("fs");
const https = require("https");

const bodyParser = require("body-parser");
const express = require("express");
const jwt = require("jsonwebtoken");

const {UserDatabase} = require("../model/UserDatabase.js");

const OK = 200;
const CREATED = 201;
const SEE_OTHER = 303;
const BAD_REQUEST = 400;
const UNAUTHORIZED = 401;
const NOT_FOUND = 404;
const INTERNAL_SERVER_ERROR = 500;

const authSecret = "superSecretString";

class Server {
    /**
     * Create the server
     * @param {Number} port - port to run on
     * @param {Number} authTimeout - time after which an auth token should become invalid (in seconds)
     * @param {String} sslDir - directory in which the key and certificate are located
     * @param {Db} db - Mongo database instance
     */
    constructor(port, authTimeout, sslDir, db) {
        this.port = port;
        this.authTimeout = authTimeout;
        this.keyPath = sslDir + "key.pem";
        this.certPath = sslDir + "cert.pem";
        this.userDb = new UserDatabase(db);
    }

    /**
     * Start the HTTPS server
     */
    serve() {
        const app = express();

        app.use("/users/:id", bodyParser.json());

        // Bind the context, otherwise it won't persist when the functions are called
        app.put("/users/:id",      this.createUser.bind(this));
        app.put("/users/:id/auth", this.logIn.bind(this));
        app.get("/users/:id",      this.getUser.bind(this));

        const options = {
            key: fs.readFileSync(this.keyPath),
            cert: fs.readFileSync(this.certPath),
        };
        
        const server = https.createServer(options, app);

        server.listen(this.port, () => {
            console.log(`Listening on port ${this.port}...`);
        });
    }

    /**
     * Create a user if it doesn't already exist
     * @param {Object} req - request object provided by Express
     * @param {Object} res - response object provided by Express
     */
    createUser(req, res) {
        const id = decodeURIComponent(req.params.id);
        const password = decodeURIComponent(req.query.pw);
        const body = req.body;

        if (!id || !password || !body) {
            res.status(BAD_REQUEST).send({
                status: "ERROR_BAD_REQUEST",
                info: "ID, password, or body is invalid"
            });
            return;
        }

        this.userDb.createUser(id, password, body)
            .then((result) => {
                // If the user already existed, send status 303
                if (result === "already exists") {
                    res.append("Location", this.getRequestBaseUrl(req) + `users/${id}`);
                    res.status(SEE_OTHER).send({
                        status: "EXISTS",
                        info: `user ${id} already exists`
                    });
                }
                else {
                    res.append("Location", this.getRequestBaseUrl(req) + `users/${id}`);
                    res.status(CREATED).send({
                        status: "CREATED",
                        authToken: this.createAuthToken(id)
                    });
                }
            })
            .catch((err) => {
                console.error(err);
                res.status(INTERNAL_SERVER_ERROR).send({
                    status: "ERROR_INTERNAL_SERVER_ERROR",
                    info: "server encountered unexpected error"
                });
            });
    }

    /**
     * Check if the password provided for the user is valid and send an authentication token to the client if so
     * @param {Object} req - request object provided by Express
     * @param {Object} res - response object provided by Express
     */
    logIn(req, res) {
        const id = decodeURIComponent(req.params.id);
        const body = req.body;

        if (!id || !body) {
            res.status(BAD_REQUEST).send({
                status: "ERROR_BAD_REQUEST",
                info: "ID or body is invalid"
            });
        }
        else if (!body.pw) {
            res.status(UNAUTHORIZED).send({
                status: "ERROR_UNAUTHORIZED",
                info: `/users/${id}/auth requires a valid 'pw' password query parameter`
            });
        }
        else {
            this.userDb.checkPassword(id, body.pw)
                .then((result) => {
                    if (result === "not found") {
                        res.status(NOT_FOUND).send({
                            status: "ERROR_NOT_FOUND",
                            info: `user ${id} not found`
                        });
                    }
                    else if (result === false) {
                        res.status(UNAUTHORIZED).send({
                            status: "ERROR_UNAUTHORIZED",
                            info: `/users/${id}/auth requires a valid 'pw' password query parameter`
                        });
                    }
                    else if (result === true) {
                        res.status(OK).send({
                            status: "OK",
                            authToken: this.createAuthToken(id)
                        });
                    }
                })
                .catch((err) => {
                    console.error(err);
                    res.status(INTERNAL_SERVER_ERROR).send({
                        status: "ERROR_INTERNAL_SERVER_ERROR",
                        info: "server encountered unexpected error"
                    });
                });
        }
    }

    /**
     * Get the user data stored in the database for the user ID if the authentication token is valid
     * @param {Object} req - request object provided by Express
     * @param {Object} res - response object provided by Express
     */
    getUser(req, res) {
        const id = decodeURIComponent(req.params.id);

        if (!id) {
            res.status(BAD_REQUEST).send({
                status: "ERROR_BAD_REQUEST",
                info: "ID is invalid"
            });
            return;
        }

        const authValue = req.header("authorization");
        const authValueSplit = authValue && authValue.split(" ");

        if (!authValue || authValueSplit[0].toLowerCase() !== "bearer" || !authValueSplit[1]) {
            res.status(UNAUTHORIZED).send({
                status: "ERROR_UNAUTHORIZED",
                info: `/users/${id} requires a bearer authorization header`
            });
            return;
        }

        const authToken = authValueSplit[1];

        if (this.checkAuthToken(authToken)) {
            this.userDb.getUser(id)
                .then((result) => {
                    if (result === "not found") {
                        res.status(NOT_FOUND).send({
                            status: "ERROR_NOT_FOUND",
                            info: `user ${id} not found`
                        });
                    }
                    else {
                        res.json(result);
                    }
                })
                .catch((err) => {
                    console.error(err);
                    res.status(INTERNAL_SERVER_ERROR).send({
                        status: "ERROR_INTERNAL_SERVER_ERROR",
                        info: "server encountered unexpected error"
                    });
                });
        }
        else {
            res.status(UNAUTHORIZED).send({
                status: "ERROR_UNAUTHORIZED",
                info: `/users/${id} requires a bearer authorization header`
            });
        }
    }

    /**
     * Get the URL of this server (where the request was sent), including the port
     * @param {Object} req - request object provided by Express
     * @return {String} url
     */
    getRequestBaseUrl(req) {
        return `${req.protocol}://${req.hostname}:${this.port}/`;
    }

    /**
     * Create a new authentication token (to be stored client-side and sent with future requests)
     * @param {Number} id - id of user who sent the request
     * @return {String} token
     */
    createAuthToken(id) {
        const payload = {
            id: id
        };

        const options = {
            expiresIn: this.authTimeout
        };

        return jwt.sign(payload, authSecret, options);
    }

    /**
     * Check if the authentication token is valid
     * @param {String} authToken - the token to check
     * @return {Boolean}
     */
    checkAuthToken(authToken) {
        const options = {
            maxAge: this.authTimeout
        };
        
        try {
            const payload = jwt.verify(authToken, authSecret, options);
            
            //console.log(payload);
            
            return true;
        }
        catch (err) {
            console.error(err.message);
            
            return false;
        }
    }
}

module.exports = {
    Server: Server
};
