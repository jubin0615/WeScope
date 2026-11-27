from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    price = db.Column(db.Numeric(10, 2))


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    product_id = db.Column(db.Integer)
    quantity = db.Column(db.Integer)
    total = db.Column(db.Numeric(10, 2))
    status = db.Column(db.String(20))

    def to_dict(self):
        return {"id": self.id, "product_id": self.product_id, "quantity": self.quantity, "total": str(self.total)}
