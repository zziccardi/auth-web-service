
const bcrypt = require("bcrypt");

const dbCollectionName = "users";

class UserDatabase {
    /**
     * Manages access to the users database
     * @param {Db} db - Mongo database instance
     */
    constructor(db) {
        this.db = db;
        this.users = db.collection(dbCollectionName);
    }

    /**
     * Create a new user if a user with the provided ID doesn't already exist.
     * @param {String} id - id of user
     * @param {String} password - plain-text password to be hashed and stored
     * @param {Object} data - data to store in the database under the user ID
     * @return {Promise}
     */
    createUser(id, password, data) {
        if (!id || typeof id !== "string" || !password || typeof password !== "string" || !data) {
            return Promise.reject(new Error("Invalid parameters"));
        }
        
        // First check if there already is a user with this id
        return this.users.find({_id: id}).toArray()
            .then((docs) => {
                return new Promise((resolve, reject) => {
                    // If this user already exists, let the server know
                    if (docs.length === 1) {
                        resolve("already exists");
                    }
                    // Otherwise, create a new user
                    else if (docs.length === 0) {
                        // Passwords should really go in a separate database but that's not necessary for this assignment
                        return bcrypt.hash(password, 10)
                            .then((hashedPassword) => {
                                data._id = id;
                                data._pw = hashedPassword;

                                return this.users.insertOne(data)
                                    .then((result) => {
                                        if (result.insertedCount !== 1) {
                                            reject(new Error("Did not insert 1 user"));
                                        }
                                        else {
                                            resolve(true);
                                        }
                                    });
                            });
                    }
                    // This shouldn't ever happen
                    else {
                        console.error("Multiple docs found for user with id " + id + ":");
                        console.error(docs);
                        reject(new Error("Multiple docs found for user with id " + id));
                    }
                });
            });
    }

    /**
     * Check whether the plain-text password provided matches the hashed password stored in the database
     * @param {String} id - id of user
     * @param {String} password - plain-text password to check against the hashed password
     * @return {Promise}
     */
    checkPassword(id, password) {
        if (!id || typeof id !== "string" || !password || typeof password !== "string") {
            return Promise.reject(new Error("Invalid parameters"));
        }
        
        return this.users.find({_id: id}).toArray()
            .then((docs) => {
                return new Promise((resolve, reject) => {
                    // If a user with this ID is found, check the password
                    if (docs.length === 1) {
                        const hashedPassword = docs[0]._pw;

                        return bcrypt.compare(password, hashedPassword)
                            .then((result) => {
                                if (result === true) {
                                    resolve(true);
                                }
                                else {
                                    resolve(false);
                                }
                            });
                    }
                    // If a user with this ID is not found, let the server know
                    else if (docs.length === 0) {
                        resolve("not found");
                    }
                    // This shouldn't ever happen
                    else {
                        console.error("Multiple docs found for user with id " + id + ":");
                        console.error(docs);
                        reject(new Error("Multiple docs found for user with id " + id));
                    }
                });
            });
    }

    /**
     * Find a user in the database and return it
     * @param {String} id - id of user
     * @return {Promise}
     */
    getUser(id) {
        if (!id || typeof id !== "string") {
            return Promise.reject(new Error("Invalid parameters"));
        }
        
        return this.users.find({_id: id}).toArray()
            .then((docs) => {
                return new Promise((resolve, reject) => {
                    // If a user with this ID is found, delete the id and password and resolve it
                    if (docs.length === 1) {
                        delete docs[0]._id;
                        delete docs[0]._pw;
                        resolve(docs[0]);
                    }
                    // If a user with this ID is not found, let the server know
                    else if (docs.length === 0) {
                        resolve("not found");
                    }
                    // This shouldn't ever happen
                    else {
                        console.error("Multiple docs found for user with id " + id + ":");
                        console.error(docs);
                        reject(new Error("Multiple docs found for user with id " + id));
                    }
                });
            });
    }
}

module.exports = {
    UserDatabase: UserDatabase
};
