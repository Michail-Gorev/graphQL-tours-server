const { ApolloServer } = require('apollo-server');
const { Sequelize, DataTypes } = require('sequelize');
const { makeExecutableSchema } = require('@graphql-tools/schema');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Конфигурация
const JWT_SECRET = 'your-secret-key';
const SALT_ROUNDS = 10;

// Инициализация базы данных
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: './tours-agency.db',
  logging: console.log, // Можно отключить в продакшене
});

// Модель Museum
const Museum = sequelize.define('Museum', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  city: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// Модель User
const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
    },
  },
  passwordHash: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// Модель Tour
const Tour = sequelize.define('Tour', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  title: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  city: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  price: {
    type: DataTypes.DOUBLE,
    allowNull: false,
  },
  transfer: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
  },
});

// Модель Order
const Order = sequelize.define('Order', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  cost: {
    type: DataTypes.DOUBLE,
    allowNull: false,
  },
  isConfirmed: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  timestamp: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
  },
});

// Настройка связей
Tour.belongsToMany(Museum, { 
  through: 'TourMuseums',
  as: 'museums',
  foreignKey: 'tourId',
  otherKey: 'museumId'
});

Museum.belongsToMany(Tour, { 
  through: 'TourMuseums',
  as: 'tours',
  foreignKey: 'museumId',
  otherKey: 'tourId'
});

User.hasMany(Order);
Order.belongsTo(User);

Tour.hasMany(Order);
Order.belongsTo(Tour);

// GraphQL схема
const typeDefs = `
    type Query {
    # Туры
    tours: [Tour!]!
    tour(id: ID!): Tour
    activeTours: [Tour!]!
    toursByCity(city: String!): [Tour!]!
    
    # Музеи
    museums: [Museum!]!
    museum(id: ID!): Museum
    
    # Пользователи
    users: [User!]!
    user(id: ID!): User
    currentUser: User
    
    # Заказы
    orders: [Order!]!
    order(id: ID!): Order
    userOrders(userId: ID!): [Order!]!
  }
  
  type Mutation {
    # Музеи
    createMuseum(input: MuseumInput!): Museum!
    updateMuseum(id: ID!, input: MuseumInput!): Museum!
    deleteMuseum(id: ID!): Boolean!
    
    # Туры
    createTour(input: TourInput!): Tour!
    updateTour(id: ID!, input: TourInput!): Tour!
    deleteTour(id: ID!): Boolean!
    toggleTourStatus(id: ID!): Tour!
    
    # Пользователи
    createUser(input: UserInput!): AuthPayload!
    login(input: LoginInput!): AuthPayload!
    updateUser(id: ID!, input: UserInput!): User!
    deleteUser(id: ID!): Boolean!
    
    # Заказы
    createOrder(input: OrderInput!): Order!
    confirmOrder(id: ID!): Order!
    cancelOrder(id: ID!): Order!
  }
  
  # Типы данных
  type Museum {
    id: ID!
    name: String!
    city: String!
  }
  
  type Tour {
    id: ID!
    title: String!
    description: String!
    city: String!
    price: Float!
    transfer: Boolean!
    isActive: Boolean!
    museums: [Museum!]!
  }
  
  type User {
    id: ID!
    firstName: String!
    lastName: String!
    email: String!
    orders: [Order!]!
  }
  
  type Order {
    id: ID!
    tour: Tour!
    cost: Float!
    isConfirmed: Boolean!
    timestamp: String!
    user: User!
  }
  
  type AuthPayload {
    token: String!
    user: User!
  }
  
  # Input типы
  input MuseumInput {
    name: String!
    city: String!
  }
  
  input TourInput {
    title: String!
    description: String!
    city: String!
    price: Float!
    transfer: Boolean
    isActive: Boolean
    museumIds: [ID!]
  }
  
  input UserInput {
    firstName: String!
    lastName: String!
    email: String!
    password: String!
  }
  
  input OrderInput {
    tourId: ID!
    userId: ID!
    cost: Float!
  }
  
  input LoginInput {
    email: String!
    password: String!
  }
`;

// Реализация резолверов
const resolvers = {
  Query: {
    tours: async () => {
      return await Tour.findAll({
        include: [{
          model: Museum,
          as: 'museums',
          through: { attributes: [] }
        }]
      });
    },
    tour: async (_, { id }) => {
      return await Tour.findByPk(id, {
        include: [{
          model: Museum,
          as: 'museums',
          through: { attributes: [] }
        }]
      });
    },
    activeTours: async () => {
      return await Tour.findAll({
        where: { isActive: true },
        include: [{
          model: Museum,
          as: 'museums',
          through: { attributes: [] }
        }]
      });
    },
    toursByCity: async (_, { city }) => {
      return await Tour.findAll({
        where: { city },
        include: [{
          model: Museum,
          as: 'museums',
          through: { attributes: [] }
        }]
      });
    },
    museums: async () => await Museum.findAll(),
    museum: async (_, { id }) => await Museum.findByPk(id),
    users: async () => await User.findAll(),
    user: async (_, { id }) => await User.findByPk(id, { include: Order }),
    currentUser: async (_, __, context) => {
      if (!context.user) throw new Error('Not authenticated');
      return await User.findByPk(context.user.id, { include: Order });
    },
    orders: async () => await Order.findAll({ include: [Tour, User] }),
    order: async (_, { id }) => await Order.findByPk(id, { include: [Tour, User] }),
    userOrders: async (_, { userId }) => {
      return await Order.findAll({
        where: { userId },
        include: [Tour, User]
      });
    },
  },

  Tour: {
    museums: async (tour) => {
      if (tour.museums) return tour.museums;
      const t = await Tour.findByPk(tour.id, {
        include: [{
          model: Museum,
          as: 'museums',
          through: { attributes: [] }
        }]
      });
      return t ? t.museums : [];
    }
  },

  Mutation: {
    createMuseum: async (_, { input }) => await Museum.create(input),
    updateMuseum: async (_, { id, input }) => {
      const museum = await Museum.findByPk(id);
      if (!museum) throw new Error('Museum not found');
      await museum.update(input);
      return museum;
    },
    deleteMuseum: async (_, { id }) => {
      const deleted = await Museum.destroy({ where: { id } });
      return deleted > 0;
    },

    createTour: async (_, { input }) => {
      const { museumIds, ...tourData } = input;
      const tour = await Tour.create({
        ...tourData,
        transfer: tourData.transfer || false,
        isActive: tourData.isActive !== undefined ? tourData.isActive : true,
      });
      
      if (museumIds && museumIds.length > 0) {
        const museums = await Museum.findAll({ where: { id: museumIds } });
        await tour.setMuseums(museums);
      }
      
      return tour;
    },
    updateTour: async (_, { id, input }) => {
      const { museumIds, ...tourData } = input;
      const tour = await Tour.findByPk(id);
      if (!tour) throw new Error('Tour not found');
      
      await tour.update(tourData);
      
      if (museumIds) {
        const museums = await Museum.findAll({ where: { id: museumIds } });
        await tour.setMuseums(museums);
      }
      
      return tour;
    },
    deleteTour: async (_, { id }) => {
      const deleted = await Tour.destroy({ where: { id } });
      return deleted > 0;
    },
    toggleTourStatus: async (_, { id }) => {
      const tour = await Tour.findByPk(id);
      if (!tour) throw new Error('Tour not found');
      await tour.update({ isActive: !tour.isActive });
      return tour;
    },

    createUser: async (_, { input }) => {
      const { password, ...userData } = input;
      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
      
      const user = await User.create({
        ...userData,
        passwordHash,
      });
      
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
      
      return {
        token,
        user,
      };
    },
    login: async (_, { input }) => {
      const { email, password } = input;
      const user = await User.findOne({ where: { email } });
      
      if (!user) throw new Error('Invalid credentials');
      
      const valid = await bcrypt.compare(password, user.passwordHash);
      if (!valid) throw new Error('Invalid credentials');
      
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
      
      return {
        token,
        user,
      };
    },
    updateUser: async (_, { id, input }) => {
      const user = await User.findByPk(id);
      if (!user) throw new Error('User not found');
      
      const { password, ...userData } = input;
      const updateData = { ...userData };
      
      if (password) {
        updateData.passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
      }
      
      await user.update(updateData);
      return user;
    },
    deleteUser: async (_, { id }) => {
      const deleted = await User.destroy({ where: { id } });
      return deleted > 0;
    },

    createOrder: async (_, { input }, context) => {
      if (!context.user) throw new Error('Not authenticated');
      
      const { tourId, cost } = input;
      const tour = await Tour.findByPk(tourId);
      if (!tour) throw new Error('Tour not found');
      
      const order = await Order.create({
        tourId,
        userId: context.user.id,
        cost,
        isConfirmed: false,
      });
      
      return order;
    },
    confirmOrder: async (_, { id }, context) => {
      if (!context.user) throw new Error('Not authenticated');
      
      const order = await Order.findByPk(id, { include: [User] });
      if (!order) throw new Error('Order not found');
      
      if (order.user.id !== context.user.id) {
        throw new Error('Not authorized');
      }
      
      await order.update({ isConfirmed: true });
      return order;
    },
    cancelOrder: async (_, { id }, context) => {
      if (!context.user) throw new Error('Not authenticated');
      
      const order = await Order.findByPk(id, { include: [User] });
      if (!order) throw new Error('Order not found');
      
      if (order.user.id !== context.user.id) {
        throw new Error('Not authorized');
      }
      
      await order.destroy();
      return order;
    },
  },
};

// Создание схемы
const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

// Контекст с аутентификацией
const context = async ({ req }) => {
  const token = req.headers.authorization || '';
  try {
    if (token) {
      const decoded = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
      const user = await User.findByPk(decoded.id);
      return { user };
    }
    return {};
  } catch (error) {
    return {};
  }
};

// Инициализация сервера
const server = new ApolloServer({
  schema,
  context,
  introspection: true,
});

// Запуск сервера
async function startServer() {
  try {
    // Синхронизация моделей с базой данных без очистки существующих данных
    await sequelize.sync();
    
    const { url } = await server.listen();
    console.log(`Server ready at ${url}`);
  } catch (error) {
    console.error('Error starting server:', error);
  }
}

startServer();
