const mongoose = require('mongoose');

const connectMongo = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('🎻 Connexion à MongoDB réussie.');
  } catch (error) {
    console.error('❌ Erreur de connexion à MongoDB :', error.message);
    // arrête l'exécution du serveur si la connexion à la base de données échoue
    process.exit(1); 
  }
};

module.exports = connectMongo;
