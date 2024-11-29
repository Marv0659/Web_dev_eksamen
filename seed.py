import x
import uuid
import time
import random
from werkzeug.security import generate_password_hash
from faker import Faker

fake = Faker()

from icecream import ic
ic.configureOutput(prefix=f'***** | ', includeContext=True)

# Connect to the database
db, cursor = x.db()

def insert_user(user):
    """
    Inserts a user into the database.
    """
    q = """
        INSERT INTO users
        VALUES (%s, %s ,%s ,%s ,%s ,%s ,%s ,%s ,%s ,%s ,%s ,%s)
    """
    values = tuple(user.values())
    cursor.execute(q, values)

def insert_user_with_role(user, role_pk):
    """
    Inserts a user and assigns them a role.
    """
    insert_user(user)
    q = """
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk)
        VALUES (%s, %s)
    """
    cursor.execute(q, (user["user_pk"], role_pk))

try:
    ##############################
    # Drop tables if they exist
    cursor.execute("DROP TABLE IF EXISTS items")  # dependent table
    cursor.execute("DROP TABLE IF EXISTS users_roles")  # dependent table
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS roles")

    ##############################
    # Create tables
    cursor.execute("""
        CREATE TABLE users (
            user_pk CHAR(36),
            user_name VARCHAR(20) NOT NULL,
            user_last_name VARCHAR(20) NOT NULL,
            user_email VARCHAR(100) NOT NULL UNIQUE,
            user_password VARCHAR(255) NOT NULL,
            user_avatar VARCHAR(50),
            user_created_at INTEGER UNSIGNED,
            user_deleted_at INTEGER UNSIGNED,
            user_blocked_at INTEGER UNSIGNED,
            user_updated_at INTEGER UNSIGNED,
            user_verified_at INTEGER UNSIGNED,
            user_verification_key CHAR(36),
            PRIMARY KEY(user_pk)
        )
    """)

    cursor.execute("""
        CREATE TABLE items (
            item_pk CHAR(36),
            item_user_fk CHAR(36),
            item_title VARCHAR(50) NOT NULL,
            item_price DECIMAL(5,2) NOT NULL,
            item_image VARCHAR(50),
            PRIMARY KEY(item_pk),
            FOREIGN KEY (item_user_fk) REFERENCES users(user_pk) ON DELETE CASCADE ON UPDATE RESTRICT
        )
    """)

    cursor.execute("""
        CREATE TABLE roles (
            role_pk CHAR(36),
            role_name VARCHAR(10) NOT NULL UNIQUE,
            PRIMARY KEY(role_pk)
        )
    """)

    cursor.execute("""
        CREATE TABLE users_roles (
            user_role_user_fk CHAR(36),
            user_role_role_fk CHAR(36),
            PRIMARY KEY(user_role_user_fk, user_role_role_fk),
            FOREIGN KEY (user_role_user_fk) REFERENCES users(user_pk) ON DELETE CASCADE ON UPDATE RESTRICT,
            FOREIGN KEY (user_role_role_fk) REFERENCES roles(role_pk) ON DELETE CASCADE ON UPDATE RESTRICT
        )
    """)

    ##############################
    # Insert roles
    cursor.execute("""
        INSERT INTO roles (role_pk, role_name)
        VALUES (%s, %s), (%s, %s), (%s, %s), (%s, %s)
    """, (
        x.ADMIN_ROLE_PK, "admin",
        x.CUSTOMER_ROLE_PK, "customer",
        x.PARTNER_ROLE_PK, "partner",
        x.RESTAURANT_ROLE_PK, "restaurant"
    ))

    ##############################
    # Insert admin user
    admin_user = {
        "user_pk": str(uuid.uuid4()),
        "user_name": "Santiago",
        "user_last_name": "Donoso",
        "user_email": "admin@fulldemo.com",
        "user_password": generate_password_hash("password"),
        "user_avatar": "profile_10.jpg",
        "user_created_at": int(time.time()),
        "user_deleted_at": 0,
        "user_blocked_at": 0,
        "user_updated_at": 0,
        "user_verified_at": int(time.time()),
        "user_verification_key": str(uuid.uuid4())
    }
    insert_user_with_role(admin_user, x.ADMIN_ROLE_PK)

    ##############################
    # Insert 50 customers
    domains = ["example.com", "testsite.org", "mydomain.net", "website.co", "fakemail.io"]
    for _ in range(50):
        user = {
            "user_pk": str(uuid.uuid4()),
            "user_name": fake.first_name(),
            "user_last_name": fake.last_name(),
            "user_email": fake.unique.user_name() + "@" + random.choice(domains),
            "user_password": generate_password_hash("password"),
            "user_avatar": "profile_" + str(random.randint(1, 100)) + ".jpg",
            "user_created_at": int(time.time()),
            "user_deleted_at": 0,
            "user_blocked_at": 0,
            "user_updated_at": 0,
            "user_verified_at": random.choice([0, int(time.time())]),
            "user_verification_key": str(uuid.uuid4())
        }
        insert_user_with_role(user, x.CUSTOMER_ROLE_PK)

    ##############################
    # Insert 50 partners
    for _ in range(50):
        user = {
            "user_pk": str(uuid.uuid4()),
            "user_name": fake.first_name(),
            "user_last_name": fake.last_name(),
            "user_email": fake.unique.email(),
            "user_password": generate_password_hash("password"),
            "user_avatar": "profile_" + str(random.randint(1, 100)) + ".jpg",
            "user_created_at": int(time.time()),
            "user_deleted_at": 0,
            "user_blocked_at": 0,
            "user_updated_at": 0,
            "user_verified_at": random.choice([0, int(time.time())]),
            "user_verification_key": str(uuid.uuid4())
        }
        insert_user_with_role(user, x.PARTNER_ROLE_PK)

    ##############################
    # Insert 50 restaurants and their items
    dishes = ["Pizza", "Burger", "Sushi", "Pasta", "Salad"]
    for _ in range(50):
        user = {
            "user_pk": str(uuid.uuid4()),
            "user_name": fake.first_name(),
            "user_last_name": fake.last_name(),
            "user_email": fake.unique.email(),
            "user_password": generate_password_hash("password"),
            "user_avatar": "profile_" + str(random.randint(1, 100)) + ".jpg",
            "user_created_at": int(time.time()),
            "user_deleted_at": 0,
            "user_blocked_at": 0,
            "user_updated_at": 0,
            "user_verified_at": random.choice([0, int(time.time())]),
            "user_verification_key": str(uuid.uuid4())
        }
        insert_user_with_role(user, x.RESTAURANT_ROLE_PK)

        for _ in range(random.randint(5, 15)):
            cursor.execute("""
                INSERT INTO items (item_pk, item_user_fk, item_title, item_price, item_image)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                str(uuid.uuid4()), user["user_pk"], random.choice(dishes),
                round(random.uniform(10, 100), 2), f"dish_{random.randint(1, 100)}.jpg"
            ))

    ##############################
    db.commit()
    ic("Data seeded successfully!")

except Exception as ex:
    ic(ex)
    if "db" in locals(): db.rollback()

finally:
    if "cursor" in locals(): cursor.close()
    if "db" in locals(): db.close()