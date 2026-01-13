import express from 'express';

const app = express();

app.get('/', (req, res) => {
  res.send('Hello from Acquisitiona!').status(200);
});

export default app;
