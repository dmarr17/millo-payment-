import { Sequelize } from 'sequelize';
import dotenv from 'dotenv';
dotenv.config();
const dialect = process.env.DB_DIALECT || 'sqlite';
const sequelize = new Sequelize(process.env.DATABASE_URL || './millo_pay_demo.sqlite', { dialect, logging: false });
(async ()=>{
  await sequelize.getQueryInterface().createTable('Users', {
    id: { type: 'INTEGER', primaryKey: true, autoIncrement: true },
    name: { type: 'VARCHAR(255)' },
    email: { type: 'VARCHAR(255)', unique: true },
    passwordHash: { type: 'TEXT' },
    createdAt: { type: 'DATETIME', allowNull: false, defaultValue: new Date() },
    updatedAt: { type: 'DATETIME', allowNull: false, defaultValue: new Date() }
  }).catch(()=>{});
  await sequelize.getQueryInterface().createTable('Transactions', {
    id: { type: 'INTEGER', primaryKey: true, autoIncrement: true },
    userId: { type: 'INTEGER' },
    amount: { type: 'FLOAT' },
    cardEncrypted: { type: 'TEXT' },
    status: { type: 'VARCHAR(40)' },
    ip: { type: 'VARCHAR(100)' },
    flagged: { type: 'BOOLEAN', defaultValue: false },
    createdAt: { type: 'DATETIME', allowNull: false, defaultValue: new Date() },
    updatedAt: { type: 'DATETIME', allowNull: false, defaultValue: new Date() }
  }).catch(()=>{});
  console.log('Migration (demo) complete.');
  process.exit(0);
})();
