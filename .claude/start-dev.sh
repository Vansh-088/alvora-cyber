#!/bin/bash
NODE=/Users/vanshdudhagra/.nvm/versions/node/v24.14.0/bin/node
APP_DIR="/Users/vanshdudhagra/Alvora cyber extension and app"

# Start backend
PORT=3001 $NODE "$APP_DIR/backend/server.js" &

# Start Vite
$NODE "$APP_DIR/node_modules/vite/bin/vite.js" --port 5175 --host
