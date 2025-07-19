const express = require('express');
const connectMongo = require('./config/connectMongo');
const dotenv = require('dotenv');
const { createUser, createUserByAdmin, loginUser, createAdmin, loginAdmin, getUsers, deleteUser, updateUser, getUser, getActionHistory, getAdminActionHistory, updateAvatar, logoutUser } = require('./controllers/userController');
const cors = require('cors');
const upload = require('./config/multer');
const multer = require('multer');
const path = require('path');

dotenv.config();
const app = express();


// accepter les requêtes depuis des origines ?
app.use(cors({
  origin: 'http://localhost:3001',
  credentials: true
}));


// Middleware
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
connectMongo();

// Page d'accueil
app.get('/', (req, res) => {
  res.send('<h1>Route d\'accueil "test technique" de Thibaut Kouame"</h1>');
});

// Routes
app.post('/grmr/users/create-account', createUser);
app.post('/grmr/users/login', loginUser);
app.post('/grmr/admin/create-account', createAdmin);
app.post('/grmr/admin/login', loginAdmin);
app.post('/grmr/admin/create-user', createUserByAdmin); 
app.get('/grmr/get-users', getUsers); 
app.delete('/grmr/admin/delete-user/:id', deleteUser);
app.put('/grmr/users/update-user/:id', updateUser);
app.get('/grmr/user/profile', getUser);
app.post('/grmr/user/logout', logoutUser);
app.put('/grmr/user/avatar', upload.single('avatar'), updateAvatar);
app.get('/grmr/admin/action-history', getActionHistory);
app.get('/grmr/admin/action-history/:adminId', getAdminActionHistory);

// middleware pour la gestion d'erreur pour multer
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'Le fichier est trop volumineux. Taille maximale: 5MB.' });
    }
    return res.status(400).json({ message: 'Erreur lors de l\'upload du fichier.' });
  }
  if (error.message === 'Seules les images sont autorisées.') {
    return res.status(400).json({ message: error.message });
  }
  next(error);
});

// start server
app.listen(process.env.PORT, () => {
  console.log(`Le serveur écoute sur le port ${process.env.PORT} 🌟`);
});
