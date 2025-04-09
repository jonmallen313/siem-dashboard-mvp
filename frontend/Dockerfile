# Step 1: Use Node.js image to build the React app
FROM node:16-slim AS build

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json from the frontend folder into the container
COPY ./package*.json ./

# Install dependencies
RUN npm install

# Copy the src folder to /app/src inside the container
COPY ./src /app/src

# Build the React app
RUN npm run build

# Step 2: Use Nginx to serve the React build
FROM nginx:alpine

# Remove default nginx static files
RUN rm -rf /usr/share/nginx/html/*

# Copy the build files from the build step to nginx's serving directory
COPY --from=build /app/build /usr/share/nginx/html

# Expose port 80 for Nginx
EXPOSE 80

# Start nginx in the foreground
CMD ["nginx", "-g", "daemon off;"]

