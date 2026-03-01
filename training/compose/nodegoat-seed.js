// NodeGoat MongoDB seed data
// Auto-executed by mongo:4.4 initdb mechanism

db = db.getSiblingDB('nodegoat');

db.counters.drop();
db.counters.insertOne({ _id: "userid", seq: 3 });

db.users.drop();
db.users.insertMany([
  {
    _id: 1,
    userName: "user1",
    firstName: "User",
    lastName: "One",
    password: "User1_123",
    email: "user1@nodegoat.com",
    isAdmin: false
  },
  {
    _id: 2,
    userName: "user2",
    firstName: "User",
    lastName: "Two",
    password: "User2_123",
    email: "user2@nodegoat.com",
    isAdmin: false
  },
  {
    _id: 3,
    userName: "admin",
    firstName: "Admin",
    lastName: "User",
    password: "Admin_123",
    email: "admin@nodegoat.com",
    isAdmin: true
  }
]);

db.allocations.drop();
db.allocations.insertMany([
  { odataId: 1, odataName: "Stock Allocation", userId: 1, stocks: 10, funds: 5000, retirement: 50 },
  { odataId: 2, odataName: "Fund Allocation", userId: 2, stocks: 20, funds: 3000, retirement: 30 }
]);

db.memos.drop();
db.memos.insertMany([
  { odataId: 1, odataName: "Team Update", memo: "Important security memo" }
]);

print("NodeGoat seed complete: " + db.users.count() + " users, " + db.allocations.count() + " allocations");
