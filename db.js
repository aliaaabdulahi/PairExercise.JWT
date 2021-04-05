const Sequelize = require("sequelize");
const { STRING } = Sequelize;
const config = {
  logging: false,
};
const jwt = require("jsonwebtoken");
const SECRET_KEY = process.env.JWT;
const bcrypt = require("bcrypt");

if (process.env.LOGGING) {
  delete config.logging;
}
const conn = new Sequelize(
  process.env.DATABASE_URL || "postgres://localhost/acme_db",
  config
);

const User = conn.define("user", {
  username: STRING,
  password: STRING,
});

const Note = conn.define("note", {
  text: STRING,
});

User.hasMany(Note);
Note.belongsTo(User);

User.byToken = async (token) => {
  try {
    const verifyGood = jwt.verify(token, SECRET_KEY);
    const user = await User.findByPk(verifyGood.userId);
    if (user) {
      return user;
    }
  } catch (ex) {
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  }
};

User.authenticate = async ({ username, password }) => {
  const hashed = await bcrypt.hash(password, 10);
  const correct = await bcrypt.compare(password, hashed);
  const user = await User.findOne({
    where: {
      username,
    },
  });
  if (user && correct) {
    return jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY);
  }
  const error = Error("bad credentials");
  error.status = 401;
  throw error;
};

User.beforeCreate(async (user) => {
  const hashed = await bcrypt.hash(user.password, 10);
  user.password = hashed;
});

const syncAndSeed = async () => {
  await conn.sync({ force: true });
  const credentials = [
    { username: "lucy", password: "lucy_pw" },
    { username: "moe", password: "moe_pw" },
    { username: "larry", password: "larry_pw" },
  ];
  const notes = [
    { text: "Remember to buy cheese" },
    { text: "Study Sequelize!" },
    { text: "Movie night at 8" },
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map((credential) => User.create(credential))
  );

  const [note1, note2, note3] = await Promise.all(
    notes.map((note) => Note.create(note))
  );

  note1.setUser(moe);
  note2.setUser(lucy);
  note3.setUser(larry);

  return {
    users: {
      lucy,
      moe,
      larry,
    },
    notes: {
      note1,
      note2,
      note3,
    },
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User,
    Note,
  },
};
