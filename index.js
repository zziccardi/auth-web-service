
const mongo = require("mongodb").MongoClient;

const {Server} = require("./server/Server.js");

// Get command-line arguments
const args = require("./options.js").options;

const databaseUrl = "mongodb://localhost:27017/users";

mongo.connect(databaseUrl)
    .then((db) => {
        const sslDir = (args.sslDir === ".")
            ? "./"
            : args.sslDir;
        
        const server = new Server(args.port, args.authTimeout, sslDir, db);
        
        server.serve();
        
        //db.close();
    })
    .catch((err) => console.error(err));
