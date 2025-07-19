// userController.js
const bcrypt = require('bcryptjs');
const User = require('../models/user');
const ActionHistory = require('../models/historiquDesActionsAdmin');
const { generateToken } = require('../config/jwt');
const jwt = require('jsonwebtoken');
const { SECRET } = require('../config/jwt');
const fs = require('fs');
const path = require('path');

// middleware d'authentification
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Token manquant ou invalide.' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    // Enregistrer la tentative d'accès avec token invalide
    logAction(
      'unknown',
      'unknown',
      'TOKEN_INVALIDE',
      'SYSTEME',
      null,
      `Tentative d'accès avec token invalide depuis ${req.ip}`
    );
    return res.status(401).json({ message: 'Token invalide.' });
  }
};

// middleware d'autorisation admin
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    // Enregistrer la tentative d'accès non autorisée
    logAction(
      req.user._id,
      req.user.email,
      'TENTATIVE_ACCES_NON_AUTORISE',
      'SYSTEME',
      null,
      `Tentative d'accès à une fonctionnalité admin par l'utilisateur ${req.user.email}`
    );
    return res.status(403).json({ message: 'Accès réservé uniquement aux administrateurs.' });
  }
  next();
};

// fonction pour créer un utilisateur (inscription publique)
const createUser = async (req, res) => {
  try {
    const { nom, email, password, role, actif } = req.body;

    // validation des champs requis
    if (!nom || !email || !password) {
      return res.status(400).json({ message: 'nom, email et password sont requis.' });
    }

    // hashage du mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // création de l'utilisateur
    const user = new User({
      nom,
      email,
      password: hashedPassword,
      role: role || 'user',
      actif: actif !== undefined ? actif : true
    });

    await user.save();

    // retirer le mot de passe du document renvoyé
    const userObj = user.toObject();
    delete userObj.password;

    // générer le token
    const token = generateToken({ _id: user._id, email: user.email, role: user.role });

    // réponse de succès
    res.status(201).json({ message: 'Utilisateur créé avec succès', user: userObj, token });

    //  en cas d'erreur
  } catch (error) {
    if (error.code === 11000 && error.keyPattern && error.keyPattern.email) {
      return res.status(409).json({ message: 'Cette adresse email est déjà utilisée. Veuillez en choisir une autre.' });
    }
    res.status(500).json({ message: 'Erreur lors de la création de l\'utilisateur.', error: error.message });
  }
};

// fonction pour créer un utilisateur par un admin
const createUserByAdmin = [authenticate, isAdmin, async (req, res) => {
  try {
    const { nom, email, password, role, actif } = req.body;

    // validation des champs requis
    if (!nom || !email || !password) {
      return res.status(400).json({ message: 'nom, email et password sont requis.' });
    }

    // hashage du mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // création de l'utilisateur
    const user = new User({
      nom,
      email,
      password: hashedPassword,
      role: role || 'user',
      actif: actif !== undefined ? actif : true
    });

    await user.save();

    // retirer le mot de passe du document renvoyé
    const userObj = user.toObject();
    delete userObj.password;

    // Enregistrer l'action dans l'historique
    await logAction(
      req.user._id,
      req.user.email,
      'CREATION',
      'UTILISATEUR',
      user._id,
      `Création de l'utilisateur ${nom} (${email}) avec le rôle ${role || 'user'}`
    );

    // réponse de succès (pas de token car c'est un admin qui crée)
    res.status(201).json({ message: 'Utilisateur créé avec succès par l\'administrateur', user: userObj });

  } catch (error) {
    if (error.code === 11000 && error.keyPattern && error.keyPattern.email) {
      return res.status(409).json({ message: 'Cette adresse email est déjà utilisée. Veuillez en choisir une autre.' });
    }
    res.status(500).json({ message: 'Erreur lors de la création de l\'utilisateur.', error: error.message });
  }
}];

const createAdmin = async (req, res) => {
  try {
    const { nom, email, password, role, actif } = req.body;

    // validation des champs requis
    if (!nom || !email || !password) {
      return res.status(400).json({ message: 'nom, email et password sont requis.' });
    }

    // hashage du mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // création d'un administrateur
    const user = new User({
      nom,
      email,
      password: hashedPassword,
      role: 'admin',
      actif: actif !== undefined ? actif : true
    });

    await user.save();

    // retirer le mot de passe du document renvoyé
    const userObj = user.toObject();
    delete userObj.password;

    // Enregistrer l'action dans l'historique si c'est un admin qui crée l'administrateur
    if (req.user && req.user.role === 'admin') {
      await logAction(
        req.user._id,
        req.user.email,
        'CREATION',
        'ADMINISTRATEUR',
        user._id,
        `Création de l'administrateur ${nom} (${email})`
      );
    }

    // générer le token
    const token = generateToken({ _id: user._id, email: user.email, role: user.role });

    // réponse de succès
    res.status(201).json({ message: 'Administrateur créé avec succès', user: userObj, token });

  } catch (error) {
    if (error.code === 11000 && error.keyPattern && error.keyPattern.email) {
      return res.status(409).json({ message: 'Cette adresse email est déjà utilisée. Veuillez en choisir une autre.' });
    }
    res.status(500).json({ message: 'Erreur lors de la création de l\'administrateur.', error: error.message });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(401).json({ message: 'Cette adresse email n\'est pas associée à un compte. Veuillez en créer un.' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Mot de passe incorrect.' });
  }

  // générer le token
  const token = generateToken({ _id: user._id, email: user.email, role: user.role });

  res.status(200).json({ message: `Connexion réussie. Bienvenue ${user.nom}.`, token });
};

const loginAdmin = async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    // Enregistrer la tentative de connexion avec email inexistant
    await logAction(
      'unknown',
      email,
      'TENTATIVE_CONNEXION_ECHEC',
      'SYSTEME',
      null,
      `Tentative de connexion admin avec email inexistant: ${email}`
    );
    return res.status(401).json({ message: 'Cette adresse email n\'est pas associée à un compte. Veuillez en créer un.' });
  }

  // verifiez si l'utilisateur est un administrateur avant de le connecter
  if (user.role !== 'admin') {
    // Enregistrer la tentative de connexion admin par un utilisateur non-admin
    await logAction(
      user._id,
      user.email,
      'TENTATIVE_CONNEXION_ADMIN_ECHEC',
      'SYSTEME',
      null,
      `Tentative de connexion admin par un utilisateur non-admin: ${user.email}`
    );
    return res.status(403).json({ message: 'Accès réservé uniquement aux administrateurs.' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    // Enregistrer la tentative de connexion avec mot de passe incorrect
    await logAction(
      user._id,
      user.email,
      'TENTATIVE_CONNEXION_MDP_INCORRECT',
      'SYSTEME',
      null,
      `Tentative de connexion admin avec mot de passe incorrect: ${user.email}`
    );
    return res.status(401).json({ message: 'Mot de passe incorrect.' });
  }

  // Enregistrer la connexion dans l'historique
  await logAction(
    user._id,
    user.email,
    'CONNEXION',
    'SYSTEME',
    null,
    `Connexion de l'administrateur ${user.nom} (${user.email})`
  );

  // générer le token
  const token = generateToken({ _id: user._id, email: user.email, role: user.role });

  res.status(200).json({ message: `Connexion réussie. Bienvenue ${user.nom}.`, token });
};

// function pour déconnecter un utilisateur
const logoutUser = [authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'Utilisateur non trouvé.' });
    }

    await logAction(user._id, user.email, 'DECONNEXION', 'SYSTEME', null, `Déconnexion de l'utilisateur ${user.nom} (${user.email})`);
    res.status(200).json({ message: 'Déconnexion réussie.' });
  } catch (error) {
    console.error('Erreur lors de la déconnexion:', error);
    res.status(500).json({ message: 'Erreur lors de la déconnexion.', error: error.message });
  }
}];

// fonction pour récupérer les informations de l'utilisateur connecté
const getUser = [authenticate, async (req, res) => {
  const user = await User.findById(req.user._id).select('-password');
  res.status(200).json(user);
}];

// fonction pour récupérer la liste de tous les utilisateurs
const getUsers = [authenticate, async (req, res) => {
  const users = await User.find();

  // Enregistrer l'action dans l'historique si c'est un admin
  if (req.user.role === 'admin') {
    await logAction(
      req.user._id,
      req.user.email,
      'CONSULTATION',
      'LISTE_UTILISATEURS',
      null,
      `Consultation de la liste des utilisateurs (${users.length} utilisateurs trouvés)`
    );
  }

  res.status(200).json(users);
}];

//fonction pour supprimer un utilisateur  
const deleteUser = [authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const user = await User.findById(id);
  if (!user) {
    return res.status(404).json({ message: "Utilisateur non trouvé." });
  }
  await User.findByIdAndDelete(id);

  // Enregistrer l'action dans l'historique
  await logAction(req.user._id, req.user.email, 'SUPPRESSION', 'UTILISATEUR', id, `Suppression de l'utilisateur ${user.nom} (${user.email})`);

  res.status(200).json({ message: 'Utilisateur supprimé avec succès.' });
}];

// fonction pour modifier un utilisateur
const updateUser = [authenticate, async (req, res) => {
  const { id } = req.params;
  const { nom, email, role, actif } = req.body;

  // Vérifie d'abord si l'utilisateur existe
  const existingUser = await User.findById(id);
  if (!existingUser) {
    return res.status(404).json({ message: "Utilisateur non trouvé." });
  }

  const user = await User.findByIdAndUpdate(id, { nom, email, role, actif }, { new: true });

  // Enregistrer l'action dans l'historique si c'est un admin
  if (req.user.role === 'admin') {
    const changes = [];
    if (nom !== existingUser.nom) changes.push(`nom: ${existingUser.nom} → ${nom}`);
    if (email !== existingUser.email) changes.push(`email: ${existingUser.email} → ${email}`);
    if (role !== existingUser.role) changes.push(`rôle: ${existingUser.role} → ${role}`);
    if (actif !== existingUser.actif) changes.push(`statut: ${existingUser.actif ? 'actif' : 'inactif'} → ${actif ? 'actif' : 'inactif'}`);

    const details = changes.length > 0
      ? `Modification de l'utilisateur ${existingUser.nom} (${existingUser.email}) - Changements: ${changes.join(', ')}`
      : `Modification de l'utilisateur ${existingUser.nom} (${existingUser.email})`;

    await logAction(req.user._id, req.user.email, 'MODIFICATION', 'UTILISATEUR', id, details);
  }

  res.status(200).json(user);
}];

// Fonction pour enregistrer une action dans l'historique
const logAction = async (adminId, adminName, action, targetType, targetId = null, details = null) => {
  try {
    const historyEntry = new ActionHistory({
      adminId,
      adminName,
      action,
      targetType,
      targetId,
      details
    });
    await historyEntry.save();
  } catch (error) {
    console.error('Erreur lors de l\'enregistrement de l\'action:', error);
  }
};

// Fonction pour récupérer l'historique des actions
const getActionHistory = [authenticate, isAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, adminId, action, startDate, endDate } = req.query;

    // Construire le filtre
    const filter = {};
    if (adminId) filter.adminId = adminId;
    if (action) filter.action = action;
    if (startDate || endDate) {
      filter.timestamp = {};
      if (startDate) filter.timestamp.$gte = new Date(startDate);
      if (endDate) filter.timestamp.$lte = new Date(endDate);
    }

    // Pagination
    const skip = (page - 1) * limit;

    const history = await ActionHistory.find(filter)
      .populate('adminId', 'nom email')
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await ActionHistory.countDocuments(filter);

    // Enregistrer la consultation de l'historique
    await logAction(
      req.user._id,
      req.user.email,
      'CONSULTATION',
      'HISTORIQUE',
      null,
      `Consultation de l'historique des actions (${total} actions trouvées, page ${page})`
    );

    res.status(200).json({
      history,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        itemsPerPage: parseInt(limit)
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la récupération de l\'historique.', error: error.message });
  }
}];

// Fonction pour récupérer l'historique d'un admin spécifique
const getAdminActionHistory = [authenticate, isAdmin, async (req, res) => {
  try {
    const { adminId } = req.params;
    const { page = 1, limit = 10 } = req.query;

    const skip = (page - 1) * limit;

    const history = await ActionHistory.find({ adminId })
      .populate('adminId', 'nom email')
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await ActionHistory.countDocuments({ adminId });

    // Enregistrer la consultation de l'historique d'un admin spécifique
    await logAction(
      req.user._id,
      req.user.email,
      'CONSULTATION',
      'HISTORIQUE_ADMIN',
      adminId,
      `Consultation de l'historique de l'admin ${adminId} (${total} actions trouvées, page ${page})`
    );

    res.status(200).json({
      history,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        itemsPerPage: parseInt(limit)
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la récupération de l\'historique.', error: error.message });
  }
}];

// Fonction pour mettre à jour l'avatar de l'utilisateur
const updateAvatar = [authenticate, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Aucun fichier image fourni.' });
    }

    const userId = req.user._id;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'Utilisateur non trouvé.' });
    }

    // Supprimer l'ancien avatar s'il existe
    if (user.avatar) {
      const oldAvatarPath = path.join(__dirname, '..', user.avatar);
      if (fs.existsSync(oldAvatarPath)) {
        fs.unlinkSync(oldAvatarPath);
      }
    }

    // Mettre à jour le chemin de l'avatar dans la base de données
    const avatarPath = req.file.path.replace(/\\/g, '/'); // Normaliser les chemins pour Windows
    user.avatar = avatarPath;
    await user.save();

    // Enregistrer l'action dans l'historique si c'est un admin
    if (req.user.role === 'admin') {
      await logAction(
        req.user._id,
        req.user.email,
        'MODIFICATION',
        'AVATAR',
        userId,
        `Mise à jour de l'avatar pour l'utilisateur ${user.nom} (${user.email})`
      );
    }

    // Retourner les informations de l'utilisateur sans le mot de passe
    const userObj = user.toObject();
    delete userObj.password;

    res.status(200).json({
      message: 'Avatar mis à jour avec succès.',
      user: userObj,
      avatarUrl: `/uploads/avatars/${path.basename(avatarPath)}`
    });

  } catch (error) {
    console.error('Erreur lors de la mise à jour de l\'avatar:', error);
    res.status(500).json({ message: 'Erreur lors de la mise à jour de l\'avatar.', error: error.message });
  }
}];

module.exports = { createUser, createUserByAdmin, loginUser, createAdmin, loginAdmin, getUsers, deleteUser, updateUser, getUser, getActionHistory, getAdminActionHistory, updateAvatar, logoutUser };
