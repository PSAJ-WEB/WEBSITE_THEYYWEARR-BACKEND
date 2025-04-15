use actix_cors::Cors;
use actix_files::NamedFile;
use chrono::{DateTime, Utc};
use dotenv::dotenv;
use reqwest;
use serde_json::json;
use std::collections::HashMap;
use std::env;
// use actix_web::http::header::ContentType;
use actix_multipart::Multipart; // Untuk menangani multipart form data
use actix_web::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use actix_web::{web, App, Error as ActixError, HttpResponse, HttpServer};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Duration;
use chrono::{NaiveDate, NaiveDateTime};
use futures_util::StreamExt as _; // Untuk menggunakan method next() pada stream
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::io::Write;
use thiserror::Error;
use tokio_postgres::NoTls; // Hanya impor NoTls // Untuk menulis file

// Structs for request/response handling
#[derive(Deserialize)]
struct NewUser {
    fullname: String,
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    message: String,
    fullname: String,
    id: i32,
    email: String,
    last_activity: String, // Tambahkan ini
    role: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    message: String,
}

async fn register(new_user: web::Json<NewUser>) -> Result<HttpResponse, ActixError> {
    // Connect to the database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Send verification email and get OTP
    let otp = match send_registration_email(&new_user.email).await {
        Ok(otp) => otp,
        Err(e) => {
            eprintln!("Failed to send verification email: {}", e);
            return Ok(
                HttpResponse::InternalServerError().json("Failed to send verification email")
            );
        }
    };

    // Hash the password before storing it in the database
    let hashed_password = match hash(&new_user.password, DEFAULT_COST) {
        Ok(hashed) => hashed,
        Err(_) => {
            eprintln!("Failed to hash password");
            return Ok(HttpResponse::InternalServerError().json("Failed to hash password"));
        }
    };

    // Insert user with hashed password and OTP
    let result = client
        .execute(
            "INSERT INTO users (fullname, email, password, otp, is_verify) VALUES ($1, $2, $3, $4, FALSE)",
            &[&new_user.fullname, &new_user.email, &hashed_password, &otp],
        )
        .await;

    match result {
        Ok(_) => {
            // Get the newly created user's ID
            let user_id_row = client
                .query_one("SELECT id FROM users WHERE email = $1", &[&new_user.email])
                .await
                .map_err(|e| {
                    eprintln!("Failed to fetch user ID: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to fetch user ID")
                })?;

            let user_id: i32 = user_id_row.get(0);

            // Insert a default profile for the user
            client
                .execute("INSERT INTO profiles (user_id) VALUES ($1)", &[&user_id])
                .await
                .map_err(|e| {
                    eprintln!("Failed to create default profile: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to create default profile")
                })?;
            Ok(HttpResponse::Created()
                .json("User registered. Please check your email for verification code."))
        }
        Err(e) => {
            eprintln!("Failed to create user: {}", e);
            Ok(HttpResponse::InternalServerError().json("Failed to create user"))
        }
    }
}

// Login handler
async fn login(credentials: web::Json<LoginRequest>) -> Result<HttpResponse, ActixError> {
    // Connect to database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Update query untuk mengambil role juga
    let statement = client
        .prepare("SELECT id, fullname, password, email, last_activity, role FROM users WHERE email = $1")
        .await
        .map_err(|e| {
            eprintln!("Prepare statement error: {}", e);
            actix_web::error::ErrorInternalServerError("Database statement preparation error")
        })?;

    let last_activity: NaiveDateTime = Utc::now().naive_utc();
    match client.query_opt(&statement, &[&credentials.email]).await {
        Ok(Some(row)) => {
            let id: i32 = row.get(0);
            let fullname: String = row.get(1);
            let stored_password: String = row.get(2);
            let user_email: String = row.get(3);
            let last_activity: NaiveDateTime = row.get(4);
            let role: String = row.get(5); // Ambil role dari database

            match verify(&credentials.password, &stored_password) {
                Ok(valid) => {
                    if valid {
                        client.execute(
                            "UPDATE users SET is_online = TRUE, last_activity = NOW() WHERE id = $1",
                            &[&id]
                        ).await.map_err(|e| {
                            eprintln!("Failed to update online status: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to update status")
                        })?;
                        
                        Ok(HttpResponse::Ok().json(LoginResponse {
                            message: "Login successful".to_string(),
                            fullname,
                            id,
                            email: user_email,
                            last_activity: last_activity.format("%Y-%m-%d %H:%M:%S").to_string(),
                            role, // Kirim role ke frontend
                        }))
                    } else {
                        Ok(HttpResponse::Unauthorized().json(LoginResponse {
                            message: "Invalid credentials".to_string(),
                            fullname: String::new(),
                            id: 0,
                            email: String::new(),
                            last_activity: last_activity.format("%Y-%m-%d %H:%M:%S").to_string(),
                            role: "user".to_string(),
                        }))
                    }
                }
                Err(_) => Ok(HttpResponse::InternalServerError().json(LoginResponse {
                    message: "Error verifying password".to_string(),
                    fullname: String::new(),
                    id: 0,
                    email: String::new(),
                    last_activity: last_activity.format("%Y-%m-%d %H:%M:%S").to_string(),
                    role: "user".to_string(),
                })),
            }
        }
        Ok(None) => Ok(HttpResponse::Unauthorized().json(LoginResponse {
            message: "User not found".to_string(),
            fullname: String::new(),
            id: 0,
            email: String::new(),
            last_activity: last_activity.format("%Y-%m-%d %H:%M:%S").to_string(),
            role: "user".to_string(),
        })),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json(LoginResponse {
                message: "Database error".to_string(),
                fullname: String::new(),
                id: 0,
                email: String::new(),
                last_activity: last_activity.format("%Y-%m-%d %H:%M:%S").to_string(),
                role: "user".to_string(),
            }))
        }
    }
}

#[derive(Deserialize)]
struct CheckAdminRequest {
    user_id: i32,
}

#[derive(Serialize)]
struct CheckAdminResponse {
    is_admin: bool,
}

async fn check_admin(user_id: web::Json<CheckAdminRequest>) -> Result<HttpResponse, ActixError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let row = client.query_one(
        "SELECT role FROM users WHERE id = $1",
        &[&user_id.user_id],
    )
    .await
    .map_err(|e| {
        eprintln!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    let role: String = row.get(0);
    Ok(HttpResponse::Ok().json(CheckAdminResponse {
        is_admin: role == "admin",
    }))
}

#[derive(Deserialize)]
struct LogoutRequest {
    user_id: i32,
}

async fn logout(logout_data: web::Json<LogoutRequest>) -> Result<HttpResponse, ActixError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    client
        .execute(
            "UPDATE users SET is_online = FALSE WHERE id = $1",
            &[&logout_data.user_id],
        )
        .await
        .map_err(|e| {
            eprintln!("Failed to update logout status: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update status")
        })?;

    Ok(HttpResponse::Ok().json(RegisterResponse {
        message: "Logout successful".to_string(),
    }))
}

#[derive(Debug, Deserialize)]
struct CartItemRequest {
    product_id: i32,
    color: String,
    color_code: String,
    quantity: i32,
}

#[derive(Debug, Serialize)]
struct CartItemResponse {
    id: i32,
    product_id: i32,
    product_name: String,
    product_category: String, 
    product_image: Option<String>,
    color: String,
    color_code: String,
    quantity: i32,
    price: String,
}

#[derive(Debug, Serialize)]
struct CartResponse {
    items: Vec<CartItemResponse>,
    total_price: String,
}

async fn add_to_cart(
    path: web::Path<i32>,
    cart_item: web::Json<CartItemRequest>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Get product details including category
    let product = match client.query_one(
        "SELECT name, price, category, default_image FROM products WHERE id = $1",
        &[&cart_item.product_id],
    ).await {
        Ok(row) => row,
        Err(e) => {
            eprintln!("Product not found: {}", e);
            return Err(ApiError::NotFound("Product not found".to_string()));
        }
    };

    // Try to insert or update existing cart item
    let result = match client.query_one(
        r#"
        INSERT INTO user_carts (user_id, product_id, color, color_code, quantity)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id, product_id, color_code) 
        DO UPDATE SET quantity = user_carts.quantity + EXCLUDED.quantity
        RETURNING id, quantity
        "#,
        &[
            &user_id,
            &cart_item.product_id,
            &cart_item.color,
            &cart_item.color_code,
            &cart_item.quantity,
        ],
    ).await {
        Ok(row) => row,
        Err(e) => {
            eprintln!("Failed to add to cart: {}", e);
            return Err(ApiError::DatabaseError("Failed to add to cart".to_string()));
        }
    };

    let response = CartItemResponse {
        id: result.get(0),
        product_id: cart_item.product_id,
        product_name: product.get(0),
        product_category: product.get(2),
        product_image: product.get(3),
        color: cart_item.color.clone(),
        color_code: cart_item.color_code.clone(),
        quantity: result.get(1),
        price: product.get(1),
    };

    Ok(HttpResponse::Created().json(response))
}
async fn get_cart_items(path: web::Path<i32>) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let items = client.query(
        r#"SELECT c.id, c.product_id, p.name, p.category, p.default_image, 
                  c.color, c.color_code, c.quantity, p.price
           FROM user_carts c
           JOIN products p ON c.product_id = p.id
           WHERE c.user_id = $1"#,
        &[&user_id]
    ).await?;

    let mut total_price = 0.0;
    let cart_items: Vec<CartItemResponse> = items
        .iter()
        .map(|row| {
            let price: String = row.get(8);
            let price_val = price.parse::<f64>().unwrap_or(0.0);
            total_price += price_val * row.get::<_, i32>(7) as f64;

            CartItemResponse {
                id: row.get(0),
                product_id: row.get(1),
                product_name: row.get(2),
                product_category: row.get(3),
                product_image: row.get(4),
                color: row.get(5),
                color_code: row.get(6),
                quantity: row.get(7),
                price,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(json!({
        "items": cart_items,
        "subtotal": total_price,  // Pastikan menggunakan field name 'subtotal'
        "total_price": total_price
    })))
}

async fn get_cart_count(path: web::Path<i32>) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let count = client
        .query_one(
            "SELECT COUNT(*) FROM user_carts WHERE user_id = $1",
            &[&user_id],
        )
        .await?
        .get::<_, i64>(0);

    Ok(HttpResponse::Ok().json(json!({ "count": count })))
}

async fn update_cart_item(
    path: web::Path<(i32, i32)>,
    update_data: web::Json<HashMap<String, i32>>,
) -> Result<HttpResponse, ApiError> {
    let (user_id, item_id) = path.into_inner();
    let new_quantity = update_data.get("quantity").copied().unwrap_or(1);

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let updated = client
        .execute(
            "UPDATE user_carts SET quantity = $1 WHERE id = $2 AND user_id = $3",
            &[&new_quantity, &item_id, &user_id],
        )
        .await?;

    if updated == 0 {
        return Err(ApiError::NotFound("Cart item not found".to_string()));
    }

    Ok(HttpResponse::Ok().json(json!({ "message": "Cart item updated" })))
}

async fn remove_cart_item(path: web::Path<(i32, i32)>) -> Result<HttpResponse, ApiError> {
    let (user_id, item_id) = path.into_inner();

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let deleted = client
        .execute(
            "DELETE FROM user_carts WHERE id = $1 AND user_id = $2",
            &[&item_id, &user_id],
        )
        .await?;

    if deleted == 0 {
        return Err(ApiError::NotFound("Cart item not found".to_string()));
    }

    Ok(HttpResponse::Ok().json(json!({ "message": "Cart item removed" })))
}

async fn clear_cart(path: web::Path<i32>) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    client
    .execute(
        "DELETE FROM user_carts WHERE user_id = $1",
        &[&user_id],
    )
    .await?;

    Ok(HttpResponse::Ok().json(json!({ "message": "Cart cleared" })))
}
// Struct untuk response data user
#[derive(Serialize)]
struct User {
    id: i32,
    fullname: String,
    email: String,
    password: String,
    role: String,        // Add this
    is_online: bool,     // Add this
    last_activity: Option<NaiveDateTime>,
    birthday: Option<NaiveDate>,
    gender: Option<String>,
    img: Option<String>,
}

// Handler untuk mendapatkan semua user
async fn get_users() -> Result<HttpResponse, ActixError> {
    // Koneksi ke database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Query untuk mendapatkan semua user
    let statement = client
        .prepare("SELECT id, fullname, email, password, role, is_online, last_activity FROM users")
        .await
        .map_err(|e| {
            eprintln!("Prepare statement error: {}", e);
            actix_web::error::ErrorInternalServerError("Database statement preparation error")
        })?;

    let rows = client.query(&statement, &[]).await.map_err(|e| {
        eprintln!("Query error: {}", e);
        actix_web::error::ErrorInternalServerError("Database query error")
    })?;

    // Mapping hasil query ke struct User
    let users: Vec<User> = rows
        .iter()
        .map(|row| User {
            id: row.get(0),
            fullname: row.get(1),
            email: row.get(2),
            password: row.get(3),
            role: row.get(4),          // Add this
            is_online: row.get(5),    // Add this
            last_activity: row.get(6),
            birthday: None,
            gender: None,
            img: None,
        })
        .collect();

    Ok(HttpResponse::Ok().json(users))
}

#[derive(Deserialize)]
struct UpdateUser {
    fullname: Option<String>,
    email: Option<String>,
    // password: Option<String>,
    birthday: Option<String>, // Ubah ke Option<String>
    gender: Option<String>,
    img: Option<String>,
}

async fn edit_user(
    path: web::Path<i32>,
    update_data: web::Json<UpdateUser>,
) -> Result<HttpResponse, ActixError> {
    let user_id = path.into_inner();

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let mut updates = Vec::new();
    let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
    let mut param_index = 1;

    if let Some(fullname) = &update_data.fullname {
        updates.push(format!("fullname = ${}", param_index));
        params.push(fullname);
        param_index += 1;
    }

    if let Some(email) = &update_data.email {
        updates.push(format!("email = ${}", param_index));
        params.push(email);
        param_index += 1;
    }

    // Di handler edit_user, ubah bagian birthday:
    if let Some(birthday) = &update_data.birthday {
        updates.push(format!("birthday = ${}", param_index));
        params.push(birthday);
        param_index += 1;
    }
    if let Some(gender) = &update_data.gender {
        updates.push(format!("gender = ${}", param_index));
        params.push(gender);
        param_index += 1;
    }

    if let Some(img) = &update_data.img {
        updates.push(format!("img = ${}", param_index));
        params.push(img);
        param_index += 1;
    }

    if updates.is_empty() {
        return Ok(HttpResponse::BadRequest().json(RegisterResponse {
            message: "No fields to update".to_string(),
        }));
    }

    let query = format!(
        "UPDATE users SET {} WHERE id = ${}",
        updates.join(", "),
        param_index
    );
    params.push(&user_id);

    match client.execute(&query, &params[..]).await {
        Ok(_) => Ok(HttpResponse::Ok().json(RegisterResponse {
            message: "User successfully updated".to_string(),
        })),
        Err(e) => {
            eprintln!("Error updating user: {}", e);
            Ok(HttpResponse::InternalServerError().json(RegisterResponse {
                message: "Error updating user".to_string(),
            }))
        }
    }
}

fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    format!("{:04}", rng.gen_range(0..10000))
}

async fn send_registration_email(email: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Generate 4-digit OTP
    let otp = generate_otp();

    // Create email message
    let email_message = Message::builder()
        .from("theyywearr@gmail.com".parse()?)
        .to(email.parse()?)
        .subject("Account Verification")
        .body(format!(
            "Thank you for registering!\n\n\
             Your verification code is: {}\n\n\
             Please enter this code to verify your account.",
            otp
        ))?;

    // Setup SMTP credentials
    let creds = Credentials::new(
        "theyywearr@gmail.com".to_string(),
        "fdqakyyiwofdzixz".to_string(),
    );

    // Create SMTP transport
    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    // Send email
    match mailer.send(&email_message) {
        Ok(_) => Ok(otp),
        Err(e) => Err(Box::new(e)),
    }
}

#[derive(Deserialize)]
struct VerifyOtpRequest {
    otp: String,
}

async fn verify_otp(otp_request: web::Json<VerifyOtpRequest>) -> Result<HttpResponse, ActixError> {
    // Koneksi ke database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Cek apakah OTP cocok di database
    let statement = client
        .prepare("SELECT email FROM users WHERE otp = $1 AND is_verify = FALSE")
        .await
        .map_err(|e| {
            eprintln!("Prepare statement error: {}", e);
            actix_web::error::ErrorInternalServerError("Database statement preparation error")
        })?;

    match client.query_opt(&statement, &[&otp_request.otp]).await {
        Ok(Some(row)) => {
            let email: String = row.get(0);

            // Jika OTP cocok, update status is_verify menjadi true
            let update_statement = client
                .prepare("UPDATE users SET is_verify = TRUE WHERE email = $1")
                .await
                .map_err(|e| {
                    eprintln!("Prepare update statement error: {}", e);
                    actix_web::error::ErrorInternalServerError("Database update error")
                })?;
            client
                .execute(&update_statement, &[&email])
                .await
                .map_err(|e| {
                    eprintln!("Failed to update verification status: {}", e);
                    actix_web::error::ErrorInternalServerError(
                        "Failed to update verification status",
                    )
                })?;

            Ok(HttpResponse::Ok().json(RegisterResponse {
                message: "OTP verification successful".to_string(),
            }))
        }
        Ok(None) => Ok(HttpResponse::Unauthorized().json(RegisterResponse {
            message: "Invalid OTP".to_string(),
        })),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json(RegisterResponse {
                message: "Database error".to_string(),
            }))
        }
    }
}

#[derive(Deserialize)]
struct ProfileRequest {
    email: String,
}

async fn get_profile(
    profile_request: web::Json<ProfileRequest>,
) -> Result<HttpResponse, ActixError> {
    // Connect to the database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Prepare the SQL statement
    let statement = client
        .prepare(
            "SELECT u.fullname, u.email, p.birthday, p.gender, p.img
             FROM users u
             LEFT JOIN profiles p ON u.id = p.user_id
             WHERE u.email = $1",
        )
        .await
        .map_err(|e| {
            eprintln!("Prepare statement error: {}", e);
            actix_web::error::ErrorInternalServerError("Database statement preparation error")
        })?;

    // Execute the query
    match client
        .query_opt(&statement, &[&profile_request.email])
        .await
    {
        Ok(Some(row)) => {
            let fullname: String = row.get(0);
            let email: String = row.get(1);
            let birthday_str: Option<String> = row.get(2);
            let gender: Option<String> = row.get(3);
            let img: Option<String> = row.get(4);

            // Convert birthday from Option<String> to Option<NaiveDate>
            let birthday = match birthday_str {
                Some(date_str) => NaiveDate::parse_from_str(&date_str, "%Y-%m-%d").ok(),
                None => None,
            };

            Ok(HttpResponse::Ok().json(ProfileResponse {
                fullname,
                email,
                birthday,
                gender,
                img,
            }))
        }
        Ok(None) => Ok(HttpResponse::NotFound().json("User not found")),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json("Database error"))
        }
    }
}
async fn upload_profile_picture(
    mut payload: Multipart,
    path: web::Path<i32>,
) -> Result<HttpResponse, ActixError> {
    let user_id = path.into_inner();

    // Buat direktori uploads jika belum ada
    std::fs::create_dir_all("./uploads").map_err(|e| {
        eprintln!("Failed to create uploads directory: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create uploads directory")
    })?;

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| {
            eprintln!("Multipart error: {}", e);
            actix_web::error::ErrorInternalServerError("Multipart error")
        })?;

        let content_type = field
            .content_type()
            .map(|m| m.to_string())
            .unwrap_or_default();
        let valid_types = [
            "image/jpeg",
            "image/png",
            "image/svg+xml",
            "image/gif",
            "image/webp",
        ];

        if !valid_types.iter().any(|&t| content_type.starts_with(t)) {
            return Ok(HttpResponse::BadRequest().json(RegisterResponse {
                message: "Format file tidak didukung. Hanya gambar (JPEG, PNG, SVG, GIF, WEBP) yang diizinkan".to_string(),
            }));
        }

        let ext = match content_type.as_str() {
            "image/jpeg" => "jpg",
            "image/png" => "png",
            "image/svg+xml" => "svg",
            "image/gif" => "gif",
            "image/webp" => "webp",
            _ => "bin",
        };

        let filename = format!(
            "user_{}_{}.{}",
            user_id,
            chrono::Local::now().timestamp(),
            ext
        );
        let filepath = format!("./uploads/{}", filename);

        // Simpan file
        let mut file = std::fs::File::create(&filepath).map_err(|e| {
            eprintln!("File creation error: {}", e);
            actix_web::error::ErrorInternalServerError("File creation error")
        })?;

        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|e| {
                eprintln!("Chunk error: {}", e);
                actix_web::error::ErrorInternalServerError("Chunk error")
            })?;
            file.write_all(&data).map_err(|e| {
                eprintln!("File write error: {}", e);
                actix_web::error::ErrorInternalServerError("File write error")
            })?;
        }

        // Update database
        let (client, connection) = tokio_postgres::connect(
            "postgres://postgres:erida999@localhost:5432/postgres",
            NoTls,
        )
        .await
        .map_err(|e| {
            eprintln!("Connection error: {}", e);
            actix_web::error::ErrorInternalServerError("Database connection error")
        })?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Connection error: {}", e);
            }
        });

        client
            .execute(
                "UPDATE users SET img = $1 WHERE id = $2",
                &[&filename, &user_id],
            )
            .await
            .map_err(|e| {
                eprintln!("Database update error: {}", e);
                actix_web::error::ErrorInternalServerError("Database update error")
            })?;

        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Profile picture uploaded successfully",
            "filename": filename
        })));
    }

    Ok(HttpResponse::BadRequest().json(RegisterResponse {
        message: "No file uploaded".to_string(),
    }))
}
#[derive(Serialize)]
struct ProfileResponse {
    fullname: String,
    email: String,
    birthday: Option<NaiveDate>, // Ubah ke Option<NaiveDate>
    gender: Option<String>,
    img: Option<String>,
}

#[derive(Serialize)]
struct UserResponse {
    id: i32,
    fullname: String,
    email: String,
    birthday: Option<String>, // Format "YYYY-MM-DD"
    gender: Option<String>,
    img: Option<String>,
    is_online: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_activity: Option<String>, // Format "YYYY-MM-DD HH:MM:SS"
}
async fn get_user_by_id(path: web::Path<i32>) -> Result<HttpResponse, ActixError> {
    let user_id = path.into_inner();

    // Koneksi database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    // Handle connection in background
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Prepare statement
    let statement = client
        .prepare(
            "SELECT id, fullname, email, birthday, gender, img, is_online, last_activity 
             FROM users WHERE id = $1",
        )
        .await
        .map_err(|e| {
            eprintln!("Prepare statement error: {}", e);
            actix_web::error::ErrorInternalServerError("Database statement preparation error")
        })?;

    // Execute query
    match client.query_opt(&statement, &[&user_id]).await {
        Ok(Some(row)) => {
            // Dapatkan nama file gambar dari database
            let img_filename: Option<String> = row.get(5);

            // Konversi ke URL lengkap jika ada gambar
            // In get_user_by_id or similar endpoints
            let img_url = img_filename.map(|filename| format!("/uploads/{}", filename));

            let user = UserResponse {
                id: row.get(0),
                fullname: row.get(1),
                email: row.get(2),
                birthday: row.get::<_, Option<String>>(3),
                gender: row.get(4),
                img: img_url, // Gunakan URL lengkap
                is_online: row.get(6),
                last_activity: row
                    .get::<_, Option<chrono::NaiveDateTime>>(7)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string()),
            };

            Ok(HttpResponse::Ok().json(user))
        }
        Ok(None) => Ok(HttpResponse::NotFound().json("User not found")),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json("Database error"))
        }
    }
}

async fn update_activity(path: web::Path<i32>) -> Result<HttpResponse, ActixError> {
    let user_id = path.into_inner();

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    client
        .execute(
            "UPDATE users SET last_activity = NOW() WHERE id = $1",
            &[&user_id],
        )
        .await
        .map_err(|e| {
            eprintln!("Failed to update activity: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update activity")
        })?;

    Ok(HttpResponse::Ok().json(RegisterResponse {
        message: "Activity updated".to_string(),
    }))
}

async fn get_online_users() -> Result<HttpResponse, ActixError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let statement = client
        .prepare(
            "SELECT id, fullname, email, img FROM users WHERE is_online = TRUE ORDER BY last_activity DESC"
        )
        .await
        .map_err(|e| {
            eprintln!("Prepare statement error: {}", e);
            actix_web::error::ErrorInternalServerError("Database statement preparation error")
        })?;

    let rows = client.query(&statement, &[]).await.map_err(|e| {
        eprintln!("Query error: {}", e);
        actix_web::error::ErrorInternalServerError("Database query error")
    })?;

    let users: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "id": row.get::<_, i32>(0),
                "fullname": row.get::<_, String>(1),
                "email": row.get::<_, String>(2),
                "img": row.get::<_, Option<String>>(3),
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(users))
}

async fn serve_image(path: web::Path<String>) -> Result<NamedFile, ActixError> {
    // Extract the filename from the path
    let requested_path = path.into_inner();

    // Remove any URL prefixes that might have been included
    let clean_path = requested_path
        .replace("http://", "")
        .replace("127.0.0.1:8080/", "")
        .replace("uploads/", "")
        .trim_start_matches('/')
        .to_string();

    // Determine if this is a product image or profile image
    let (base_dir, filename) = if clean_path.starts_with("products/") {
        ("uploads/", clean_path)
    } else {
        ("uploads/", clean_path)
    };

    // Construct the full filesystem path
    let filepath = std::path::Path::new(base_dir).join(filename);

    println!("Attempting to serve file from: {:?}", filepath);

    NamedFile::open(&filepath).map_err(|e| {
        eprintln!("Failed to open {:?}: {}", filepath, e);
        actix_web::error::ErrorNotFound("File not found")
    })
}
async fn deactivate_inactive_users() -> Result<(), ActixError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // 30 menit dalam detik
    let inactive_threshold = Utc::now().naive_utc() - Duration::minutes(30);

    client
        .execute(
            "UPDATE users SET is_online = FALSE WHERE last_activity < $1",
            &[&inactive_threshold],
        )
        .await
        .map_err(|e| {
            eprintln!("Failed to deactivate inactive users: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to deactivate inactive users")
        })?;

    Ok(())
}

// Tambahkan endpoint baru
async fn check_activity() -> Result<HttpResponse, ActixError> {
    deactivate_inactive_users().await?;
    Ok(HttpResponse::Ok().json(RegisterResponse {
        message: "Activity checked".to_string(),
    }))
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Internal server error")]
    InternalError,
}

impl actix_web::error::ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::DatabaseError(_) | ApiError::InternalError => {
                HttpResponse::InternalServerError().json("Internal server error")
            }
            ApiError::NotFound(msg) => HttpResponse::NotFound().json(msg),
            ApiError::Forbidden(msg) => HttpResponse::Forbidden().json(msg),
            ApiError::ValidationError(msg) => HttpResponse::BadRequest().json(msg),
        }
    }
}

impl From<tokio_postgres::Error> for ApiError {
    fn from(err: tokio_postgres::Error) -> Self {
        ApiError::DatabaseError(err.to_string())
    }
}

// Di bagian dimana Anda mendefinisikan ApiError
impl From<Box<dyn std::error::Error>> for ApiError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        ApiError::DatabaseError(err.to_string())
    }
}

#[derive(Debug, Deserialize)]
struct AddressRequest {
    recipient_name: String,
    phone_number: String,
    address: String,
    zip_code: String,
    is_default: bool,
    address_type: Option<String>, // Make this optional if you want automatic detection
    #[serde(skip_deserializing)]
    user_id: i32,
}
#[derive(Debug, Serialize)]
pub struct AddressResponse {
    pub id: i32,
    pub recipient_name: String,
    pub phone_number: String,
    pub address: String,
    pub zip_code: String,
    pub is_default: bool,
    pub address_type: String,
    // pub created_at: String,
}


async fn add_address(
    path: web::Path<i32>,
    address_data: web::Json<AddressRequest>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    let address_type = detect_address_type(&address_data.address)
        .await
        .unwrap_or("other");

    // Debug logging
    println!("Adding address for user {}: {:?}", user_id, address_data);

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Database connection error: {}", e);
        ApiError::DatabaseError("Failed to connect to database".into())
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Insert the new address
    let row = client.query_one(
        r#"
        INSERT INTO user_addresses 
        (user_id, recipient_name, phone_number, address, zip_code, is_default, address_type)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, recipient_name, phone_number, address, zip_code, is_default, address_type, created_at
        "#,
        &[
            &user_id,
            &address_data.recipient_name,
            &address_data.phone_number,
            &address_data.address,
            &address_data.zip_code,
            &address_data.is_default,
            &address_type,
        ],
        )
        .await
        .map_err(|e| {
            eprintln!("Database error: {}", e);
            ApiError::DatabaseError("Failed to insert address".into())
        })?;

    // If setting as default, update other addresses
    if address_data.is_default {
        client
            .execute(
                "UPDATE user_addresses SET is_default = false 
             WHERE user_id = $1 AND id != $2",
                &[&user_id, &row.get::<_, i32>(0)],
            )
            .await
            .map_err(|e| {
                eprintln!("Failed to update default addresses: {}", e);
                ApiError::DatabaseError("Failed to update addresses".into())
            })?;
    }

    let address = AddressResponse {
        id: row.get(0),
        recipient_name: row.get(1),
        phone_number: row.get(2),
        address: row.get(3),
        zip_code: row.get(4),
        is_default: row.get(5),
        address_type: row.get(6),
        // created_at: row.get(7),
    };

    Ok(HttpResponse::Created().json(address))
}

async fn get_user_addresses(user_id: web::Path<i32>) -> Result<HttpResponse, ApiError> {
    // Connect to database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    // Handle connection in background
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Execute query
    let rows = client
        .query(
            "SELECT id, recipient_name, phone_number, address, zip_code, is_default, address_type, created_at 
             FROM user_addresses
             WHERE user_id = $1 
             ORDER BY is_default DESC, created_at DESC",
            &[&user_id.into_inner()],
        )
        .await?;

    // Map rows to response objects
    let addresses: Vec<AddressResponse> = rows
        .iter()
        .map(|row| AddressResponse {
            id: row.get(0),
            recipient_name: row.get(1),
            phone_number: row.get(2),
            address: row.get(3),
            zip_code: row.get(4),
            is_default: row.get(5),
            address_type: row.get(6),
            // created_at: row.get(7),
        })
        .collect();

    Ok(HttpResponse::Ok().json(addresses))
}

async fn update_address(
    path: web::Path<(i32, i32)>, // (user_id, address_id)
    address_data: web::Json<AddressRequest>,
) -> Result<HttpResponse, ApiError> {
    let (user_id, address_id) = path.into_inner();

    // Automatically detect address type
    let address_type = detect_address_type(&address_data.address)
        .await
        .unwrap_or("other");

    // Connect to database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Check if address exists and belongs to user
    let owner_check: Option<i32> = client
        .query_opt(
            "SELECT user_id FROM user_addresses WHERE id = $1",
            &[&address_id],
        )
        .await?
        .map(|row| row.get(0));

    match owner_check {
        Some(owner_id) if owner_id == user_id => {
            // Address exists and belongs to user - proceed with update
            let row = client.query_one(
                "UPDATE user_addresses 
                 SET recipient_name = $1, phone_number = $2, address = $3, 
                     zip_code = $4, is_default = $5, address_type = $6, updated_at = NOW()
                 WHERE id = $7 AND user_id = $8
                 RETURNING id, recipient_name, phone_number, address, zip_code, is_default, address_type, created_at",
                &[
                    &address_data.recipient_name,
                    &address_data.phone_number,
                    &address_data.address,
                    &address_data.zip_code,
                    &address_data.is_default,
                    &address_type, // Using the detected address type
                    &address_id,
                    &user_id,
                ],
            ).await?;

            // If setting as default, update other addresses
            if address_data.is_default {
                client
                    .execute(
                        "UPDATE user_addresses SET is_default = false 
                     WHERE user_id = $1 AND id != $2",
                        &[&user_id, &address_id],
                    )
                    .await?;
            }

            let address = AddressResponse {
                id: row.get(0),
                recipient_name: row.get(1),
                phone_number: row.get(2),
                address: row.get(3),
                zip_code: row.get(4),
                is_default: row.get(5),
                address_type: row.get(6),
                // created_at: row.get(7),
            };

            Ok(HttpResponse::Ok().json(address))
        }
        Some(_) => {
            // Address exists but doesn't belong to user
            Err(ApiError::Forbidden("Not your address".to_string()))
        }
        None => {
            // Address not found
            Err(ApiError::NotFound("Address not found".to_string()))
        }
    }
}
async fn delete_address(
    path: web::Path<(i32, i32)>, // (user_id, address_id)
) -> Result<HttpResponse, ApiError> {
    let (user_id, address_id) = path.into_inner();

    // Connect to database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // First verify the address belongs to the user
    let owner_check: Option<i32> = client
        .query_opt(
            "SELECT user_id FROM user_addresses WHERE id = $1",
            &[&address_id],
        )
        .await?
        .map(|row| row.get(0));

    match owner_check {
        Some(owner_id) if owner_id == user_id => {
            // Address exists and belongs to user - proceed with deletion
            let deleted = client
                .execute(
                    "DELETE FROM user_addresses WHERE id = $1 AND user_id = $2",
                    &[&address_id, &user_id],
                )
                .await?;

            if deleted > 0 {
                Ok(HttpResponse::Ok().json("Address deleted successfully"))
            } else {
                Err(ApiError::NotFound("Address not found".to_string()))
            }
        }
        Some(_) => {
            // Address exists but doesn't belong to user
            Err(ApiError::Forbidden("Not your address".to_string()))
        }
        None => {
            // Address not found
            Err(ApiError::NotFound("Address not found".to_string()))
        }
    }
}

async fn detect_address_type(address: &str) -> Result<&'static str, Box<dyn std::error::Error>> {
    // First check for school keywords in the address string
    let school_keywords = [
        "sd",
        "smp",
        "sma",
        "smk",
        "madrasah",
        "sekolah",
        "school",
        "college",
        "university",
        "universitas",
    ];

    let lower_address = address.to_lowercase();
    for keyword in &school_keywords {
        if lower_address.contains(keyword) {
            return Ok("school");
        }
    }

    // Then proceed with Mapbox API check if no direct match found
    let client = reqwest::Client::new();
    let mapbox_token =
        "pk.eyJ1IjoiZXJpZGEiLCJhIjoiY20wb3NhZWx1MGVhYTJscjRleWE5Nzk5ZSJ9.pCU7XJHTAYNLhugjDh8ePg";
    let encoded_address = urlencoding::encode(address);
    let url = format!(
        "https://api.mapbox.com/geocoding/v5/mapbox.places/{}.json?types=address&access_token={}",
        encoded_address, mapbox_token
    );

    let response = client.get(&url).send().await?;
    let mapbox_response: serde_json::Value = response.json().await?;

    if let Some(features) = mapbox_response["features"].as_array() {
        for feature in features {
            // Check in feature text
            if let Some(text) = feature["text"].as_str() {
                let lower_text = text.to_lowercase();
                if school_keywords.iter().any(|kw| lower_text.contains(kw)) {
                    return Ok("school");
                }
            }

            // Check in properties
            if let Some(properties) = feature["properties"].as_object() {
                if let Some(category) = properties.get("category").and_then(|c| c.as_str()) {
                    if category.contains("education") {
                        return Ok("school");
                    }
                }
            }

            // Default to work for POIs
            if let Some(place_type) = feature["place_type"].as_array() {
                if place_type.contains(&"poi".into()) {
                    return Ok("work");
                }
            }
        }
    }

    // Default to home if no specific type detected
    Ok("Home")
}

#[derive(Debug, Serialize)]
pub struct OrderItem {
    pub id: i32,
    pub product_name: String,
    pub product_image: Option<String>,
    pub color: String,
    pub color_code: String,
    pub quantity: i32,
    pub price: String,
}

#[derive(Debug, Serialize)]
pub struct UserOrder {
    pub id: i32,
    pub order_date: chrono::NaiveDateTime,
    pub status: String,
    pub total_amount: String,
    pub items: Vec<OrderItem>,
}

async fn get_user_orders(user_id: web::Path<i32>) -> Result<HttpResponse, ApiError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Get orders
    let orders = client
        .query(
            "SELECT id, order_date, status, total_amount 
         FROM user_orders 
         WHERE user_id = $1
         ORDER BY order_date DESC",
            &[&user_id.into_inner()],
        )
        .await?;

    let mut user_orders = Vec::new();

    for order_row in orders {
        let order_id: i32 = order_row.get(0);

        // Get items for each order
        let items = client
            .query(
                "SELECT id, product_name, product_image, color, color_code, quantity, price
             FROM order_items
             WHERE order_id = $1",
                &[&order_id],
            )
            .await?;

        let order_items = items
            .iter()
            .map(|item_row| OrderItem {
                id: item_row.get(0),
                product_name: item_row.get(1),
                product_image: item_row.get(2),
                color: item_row.get(3),
                color_code: item_row.get(4),
                quantity: item_row.get(5),
                price: item_row.get(6),
            })
            .collect();

        user_orders.push(UserOrder {
            id: order_id,
            order_date: order_row.get(1),
            status: order_row.get(2),
            total_amount: order_row.get(3),
            items: order_items,
        });
    }

    Ok(HttpResponse::Ok().json(user_orders))
}

#[derive(Debug, Deserialize)]
struct CreateOrderRequest {
    total_amount: String,
    items: Vec<OrderItemRequest>,
    address_id: Option<i32>,  // Optional address ID
    notes: Option<String>,    // Optional notes
}

#[derive(Debug, Deserialize)]
struct OrderItemRequest {
    product_id: i32,
    product_name: String,
    product_image: Option<String>,
    color: String,
    color_code: String,
    quantity: i32,
    price: String,
    category: String,
}

async fn get_default_address(user_id: web::Path<i32>) -> Result<HttpResponse, ApiError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    match client.query_one(
        r#"
        SELECT id, recipient_name, phone_number, address, zip_code, is_default, address_type
        FROM user_addresses
        WHERE user_id = $1 AND is_default = TRUE
        LIMIT 1
        "#,
        &[&user_id.into_inner()],
    ).await {
        Ok(row) => {
            let address = AddressResponse {
                id: row.get(0),
                recipient_name: row.get(1),
                phone_number: row.get(2),
                address: row.get(3),
                zip_code: row.get(4),
                is_default: row.get(5),
                address_type: row.get(6),
                // created_at dihapus
            };
            Ok(HttpResponse::Ok().json(address))
        }
        Err(_) => Err(ApiError::NotFound("No default address found".to_string())),
    }
}

#[derive(Debug, Serialize)]
struct OrderResponse {
    id: i32,
    order_date: chrono::NaiveDateTime,
    status: String,
    total_amount: String,
    subtotal: String,
    delivery_fee: String,
}

#[derive(Debug, Serialize)]
struct PendingOrderResponse {
    order: OrderResponse,
    qr_code_url: String,
}
async fn create_order(
    path: web::Path<i32>,
    order_data: web::Json<CreateOrderRequest>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();
    
    // Input validation
    let total_amount: f64 = order_data.total_amount.parse().map_err(|_| {
        ApiError::ValidationError("Invalid total amount format".to_string())
    })?;
    
    if total_amount <= 0.0 {
        return Err(ApiError::ValidationError("Total amount must be positive".to_string()));
    }

    // Parse each item's price
    let items: Result<Vec<ParsedOrderItem>, ApiError> = order_data.items.iter()
        .map(|item| {
            let price: f64 = item.price.parse().map_err(|_| {
                ApiError::ValidationError(format!("Invalid price format for item {}", item.product_id))
            })?;
            
            Ok(ParsedOrderItem {
                product_id: item.product_id,
                product_name: item.product_name.clone(),
                product_image: item.product_image.clone(),
                color: item.color.clone(),
                color_code: item.color_code.clone(),
                quantity: item.quantity,
                price: item.price.clone(), // Keep original string for DB
                parsed_price: price,       // Parsed value for calculations
                category: item.category.clone(),
            })
        })
        .collect();

    let items = items?;
    
    // Calculate total from parsed values to verify
    let calculated_total: f64 = items.iter()
        .map(|item| item.parsed_price * item.quantity as f64)
        .sum();
    
    if (calculated_total - total_amount).abs() > 0.01 {
        return Err(ApiError::ValidationError(
            "Submitted total doesn't match calculated total".to_string()
        ));
    }


    let (mut client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await.map_err(|e| {
        eprintln!("Database connection error: {}", e);
        ApiError::DatabaseError("Failed to connect to database".into())
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Start transaction
    let transaction = client.transaction().await.map_err(|e| {
        eprintln!("Transaction error: {}", e);
        ApiError::DatabaseError("Failed to start transaction".into())
    })?;

    // 1. Create the order with address_id and notes if provided
    let order_row = transaction.query_one(
        r#"
        INSERT INTO user_orders 
            (user_id, total_amount, status, address_id, notes) 
        VALUES ($1, $2, 'pending', $3, $4)
        RETURNING id, order_date
        "#,
        &[
            &user_id, 
            &order_data.total_amount,
            &order_data.address_id,
            &order_data.notes
        ],
    ).await.map_err(|e| {
        eprintln!("Failed to create order: {}", e);
        ApiError::DatabaseError("Failed to create order".into())
    })?;

    let order_id: i32 = order_row.get(0);
    let total_amount: String = order_row.get(1);

    // 2. Add order items with category
    for item in &order_data.items {
        transaction.execute(
            r#"
            INSERT INTO order_items (
                order_id, 
                product_id,
                product_name, 
                product_image, 
                color, 
                color_code, 
                quantity, 
                price,
                category
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            &[
                &order_id,
                &item.product_id,
                &item.product_name,
                &item.product_image,
                &item.color,
                &item.color_code,
                &item.quantity,
                &item.price,
                &item.category,
            ],
        ).await.map_err(|e| {
            eprintln!("Failed to insert order item: {}", e);
            ApiError::DatabaseError("Failed to add order items".into())
        })?;
    }

    // Commit transaction
    transaction.commit().await.map_err(|e| {
        eprintln!("Failed to commit transaction: {}", e);
        ApiError::DatabaseError("Failed to complete order".into())
    })?;

    Ok(HttpResponse::Created().json(json!({
        "id": order_id,  // This is what the frontend expects as result.id
        "message": "Order created successfully",
        "total_amount": total_amount
    })))
}

struct ParsedOrderItem {
    product_id: i32,
    product_name: String,
    product_image: Option<String>,
    color: String,
    color_code: String,
    quantity: i32,
    price: String,      // Original string for DB
    parsed_price: f64,  // Parsed value for validation
    category: String,
}
// Add these structs near your other struct definitions
#[derive(Debug, Serialize)]
pub struct OrderDetailResponse {
    pub id: i32,
    pub order_date: chrono::NaiveDateTime,
    pub status: String,
    pub total_amount: String,
    pub items: Vec<OrderItem>,
    pub address: Option<AddressResponse>,
    pub notes: Option<String>,
    pub subtotal: String,
    pub delivery_fee: String,
}

#[derive(Debug, Serialize)]
pub struct PendingPaymentResponse {
    pub order: OrderDetailResponse,
}

// Handler to get order details
async fn get_order_details(
    path: web::Path<(i32, i32)>, // (user_id, order_id)
) -> Result<HttpResponse, ApiError> {
    let (user_id, order_id) = path.into_inner();

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Get order main details
    let order_row = client.query_one(
        "SELECT id, order_date, status, total_amount, notes 
         FROM user_orders 
         WHERE id = $1 AND user_id = $2",
        &[&order_id, &user_id],
    ).await?;

    // Get order items
    let items = client.query(
        "SELECT product_name, product_image, color, color_code, quantity, price
         FROM order_items
         WHERE order_id = $1",
        &[&order_id],
    ).await?;

    let order_items: Vec<OrderItem> = items
    .iter()
    .map(|row| OrderItem {
        id: row.get(0),
        product_name: row.get(1),
        product_image: row.get(2),
        color: row.get(3),
        color_code: row.get(4),
        quantity: row.get(5),
        price: row.get(6),
    })
    .collect();

    // Calculate subtotal (sum of all items' price * quantity)
    let subtotal: f64 = order_items.iter()
        .map(|item| item.price.parse::<f64>().unwrap_or(0.0) * item.quantity as f64)
        .sum();
    
    // Calculate delivery fee (10% of subtotal for example)
    let delivery_fee = subtotal * 0.1;

    // Get address if available
    let address_row = client.query_opt(
        "SELECT a.recipient_name, a.phone_number, a.address, a.zip_code, a.address_type
         FROM user_addresses a
         JOIN user_orders o ON o.address_id = a.id
         WHERE o.id = $1 AND o.user_id = $2",
        &[&order_id, &user_id],
    ).await?;

    let address = address_row.map(|row| AddressResponse {
        id: row.get(0),
        recipient_name: row.get(1),
        phone_number: row.get(2),
        address: row.get(3),
        zip_code: row.get(4),
        is_default: row.get(5),
        address_type: row.get(6),
        // created_at: row.get(7),
    });

    Ok(HttpResponse::Ok().json(OrderDetailResponse {
        id: order_row.get(0),
        order_date: order_row.get(1),
        status: order_row.get(2),
        total_amount: order_row.get(3),
        items: order_items,
        address,
        notes: order_row.get(4),
        subtotal: format!("{:.3}", subtotal),
        delivery_fee: format!("{:.3}", delivery_fee),
    }))
}

// Handler to update order notes
async fn update_order_notes(
path: web::Path<(i32, i32)>, // (user_id, order_id)
notes: web::Json<HashMap<String, String>>,
) -> Result<HttpResponse, ApiError> {
let (user_id, order_id) = path.into_inner();
let notes_text = notes.get("notes").cloned().unwrap_or_default();

let (client, connection) = tokio_postgres::connect(
"postgres://postgres:erida999@localhost:5432/postgres",
NoTls,
).await?;

tokio::spawn(async move {
if let Err(e) = connection.await {
    eprintln!("Connection error: {}", e);
}
});

client.execute(
"UPDATE user_orders SET notes = $1 
 WHERE id = $2 AND user_id = $3",
&[&notes_text, &order_id, &user_id],
).await?;

Ok(HttpResponse::Ok().json(json!({
"message": "Notes updated successfully"
})))
}
#[derive(Debug, Deserialize)]
struct UpdateProduct {
    name: Option<String>,
    category: Option<String>,
    price: Option<String>,
    default_image: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NewProduct {
    name: String,
    category: String,
    price: String,
    default_image: String,
    colors: Vec<NewProductColor>,
}

#[derive(Debug, Deserialize)]
struct NewProductColor {
    color: String,
    image: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Product {
    pub id: i32,
    pub name: String,
    pub category: String,
    pub price: String,
    pub default_image: Option<String>, // Changed to Option<String>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub liked: Option<bool>,
    pub likes_count: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProductColor {
    pub color: String,
    pub image: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProductDetail {
    pub product: Product,
    pub colors: Vec<ProductColor>,
}

async fn update_product_colors(
    path: web::Path<i32>,
    colors: web::Json<Vec<NewProductColor>>,
) -> Result<HttpResponse, ApiError> {
    let product_id = path.into_inner();

    let (mut client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Start transaction
    let transaction = client
        .transaction()
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    // Delete old colors
    transaction
        .execute(
            "DELETE FROM product_colors WHERE product_id = $1",
            &[&product_id],
        )
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    // Add new colors
    for color in colors.iter() {
        transaction
            .execute(
                "INSERT INTO product_colors (product_id, color_name, color_image) 
             VALUES ($1, $2, $3)",
                &[&product_id, &color.color, &color.image],
            )
            .await
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
    }

    // Commit transaction
    transaction
        .commit()
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(RegisterResponse {
        message: "Product colors updated successfully".to_string(),
    }))
}

async fn delete_product(path: web::Path<i32>) -> Result<HttpResponse, ApiError> {
    let product_id = path.into_inner();

    let (mut client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Start transaction
    let transaction = client
        .transaction()
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    // Delete product colors first
    transaction
        .execute(
            "DELETE FROM product_colors WHERE product_id = $1",
            &[&product_id],
        )
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    // Delete product
    let deleted = transaction
        .execute("DELETE FROM products WHERE id = $1", &[&product_id])
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    if deleted == 0 {
        return Err(ApiError::NotFound("Product not found".to_string()));
    }

    // Commit transaction
    transaction
        .commit()
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(RegisterResponse {
        message: "Product deleted successfully".to_string(),
    }))
}

async fn update_product(
    path: web::Path<i32>,
    update_data: web::Json<UpdateProduct>,
) -> Result<HttpResponse, ApiError> {
    let product_id = path.into_inner();

    let (mut client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let mut updates = Vec::new();
    let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
    let mut param_index = 1;

    if let Some(name) = &update_data.name {
        updates.push(format!("name = ${}", param_index));
        params.push(name);
        param_index += 1;
    }

    if let Some(category) = &update_data.category {
        updates.push(format!("category = ${}", param_index));
        params.push(category);
        param_index += 1;
    }

    if let Some(price) = &update_data.price {
        updates.push(format!("price = ${}", param_index));
        params.push(price);
        param_index += 1;
    }

    if let Some(default_image) = &update_data.default_image {
        updates.push(format!("default_image = ${}", param_index));
        params.push(default_image);
        param_index += 1;
    }

    if updates.is_empty() {
        return Err(ApiError::ValidationError("No fields to update".to_string()));
    }

    let query = format!(
        "UPDATE products SET {} WHERE id = ${}",
        updates.join(", "),
        param_index
    );
    params.push(&product_id);

    let updated = client
        .execute(&query, &params[..])
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    if updated == 0 {
        return Err(ApiError::NotFound("Product not found".to_string()));
    }

    Ok(HttpResponse::Ok().json(RegisterResponse {
        message: "Product updated successfully".to_string(),
    }))
}

async fn add_product(new_product: web::Json<NewProduct>) -> Result<HttpResponse, ApiError> {
    let (mut client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Start transaction
    let transaction = client
        .transaction()
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    // Insert main product
    let product_row = transaction
        .query_one(
            "INSERT INTO products (name, category, price, default_image) 
         VALUES ($1, $2, $3, $4) 
         RETURNING id",
            &[
                &new_product.name,
                &new_product.category,
                &new_product.price,
                &new_product.default_image,
            ],
        )
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    let product_id: i32 = product_row.get(0);

    // Insert all product colors
    for color in &new_product.colors {
        transaction
            .execute(
                "INSERT INTO product_colors (product_id, color_name, color_image) 
             VALUES ($1, $2, $3)",
                &[&product_id, &color.color, &color.image],
            )
            .await
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
    }

    // Commit transaction
    transaction
        .commit()
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(HttpResponse::Created().json(RegisterResponse {
        message: format!("Product {} added successfully", new_product.name),
    }))
}

async fn upload_product_image(mut payload: Multipart) -> Result<HttpResponse, ActixError> {
    // Buat direktori uploads jika belum ada
    std::fs::create_dir_all("./uploads/products").map_err(|e| {
        eprintln!("Failed to create uploads directory: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create uploads directory")
    })?;

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| {
            eprintln!("Multipart error: {}", e);
            actix_web::error::ErrorInternalServerError("Multipart error")
        })?;

        let content_type = field
            .content_type()
            .map(|m| m.to_string())
            .unwrap_or_default();
        let valid_types = [
            "image/jpeg",
            "image/png",
            "image/svg+xml",
            "image/gif",
            "image/webp",
        ];

        if !valid_types.iter().any(|&t| content_type.starts_with(t)) {
            return Ok(HttpResponse::BadRequest().json(RegisterResponse {
                message: "Format file tidak didukung. Hanya gambar (JPEG, PNG, SVG, GIF, WEBP) yang diizinkan".to_string(),
            }));
        }

        let ext = match content_type.as_str() {
            "image/jpeg" => "jpg",
            "image/png" => "png",
            "image/svg+xml" => "svg",
            "image/gif" => "gif",
            "image/webp" => "webp",
            _ => "bin",
        };

        // Generate unique filename
        let filename = format!("product_{}.{}", chrono::Local::now().timestamp_nanos(), ext);
        let filepath = format!("./uploads/products/{}", filename);

        // Simpan file
        let mut file = std::fs::File::create(&filepath).map_err(|e| {
            eprintln!("File creation error: {}", e);
            actix_web::error::ErrorInternalServerError("File creation error")
        })?;

        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|e| {
                eprintln!("Chunk error: {}", e);
                actix_web::error::ErrorInternalServerError("Chunk error")
            })?;
            file.write_all(&data).map_err(|e| {
                eprintln!("File write error: {}", e);
                actix_web::error::ErrorInternalServerError("File write error")
            })?;
        }

        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Product image uploaded successfully",
            "filename": format!("products/{}", filename)
        })));
    }

    Ok(HttpResponse::BadRequest().json(RegisterResponse {
        message: "No file uploaded".to_string(),
    }))
}

async fn get_pending_order(
    path: web::Path<(i32, i32)>, // (user_id, order_id)
) -> Result<HttpResponse, ApiError> {
    let (user_id, order_id) = path.into_inner();

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Get order details
    let order_row = client.query_one(
        "SELECT id, order_date, status, total_amount 
         FROM user_orders 
         WHERE id = $1 AND user_id = $2",
        &[&order_id, &user_id],
    )
    .await?;

    // Get order items
    let items = client.query(
        "SELECT id, product_name, product_image, color, color_code, quantity, price
         FROM order_items
         WHERE order_id = $1",
        &[&order_id],
    )
    .await?;

    // Calculate subtotal and delivery fee
    let subtotal: f64 = items.iter()
        .map(|row| {
            let price: String = row.get(6);
            let quantity: i32 = row.get(5);
            price.parse::<f64>().unwrap_or(0.0) * quantity as f64
        })
        .sum();
    
    let delivery_fee = subtotal * 0.1; // 10% of subtotal as delivery fee

    let order = OrderResponse {
        id: order_row.get(0),
        order_date: order_row.get(1),
        status: order_row.get(2),
        total_amount: order_row.get(3),
        subtotal: format!("{:.2}", subtotal),
        delivery_fee: format!("{:.2}", delivery_fee),
    };

    // In a real app, you would generate a dynamic QR code here
    // For now, we'll use a static image
    let qr_code_url = "/uploads/qris.jpg".to_string();

    Ok(HttpResponse::Ok().json(PendingOrderResponse {
        order,
        qr_code_url,
    }))
}

async fn get_products() -> Result<HttpResponse, ApiError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let products = client.query(
        r#"
        SELECT 
            p.id, 
            p.name, 
            p.category, 
            p.price, 
            p.default_image, 
            p.description,
            COUNT(pl.id) as likes_count
        FROM products p
        LEFT JOIN product_likes pl ON p.id = pl.product_id
        GROUP BY p.id
        ORDER BY p.id ASC
        "#,
        &[],
    ).await?;

    let product_list: Vec<Product> = products
        .iter()
        .map(|row| Product {
            id: row.get(0),
            name: row.get(1),
            category: row.get(2),
            price: row.get(3),
            default_image: row.get(4),
            description: row.get(5),
            liked: None,  // You can set this based on user context if needed
            likes_count: row.get(6),  // This now matches the struct
        })
        .collect();

    Ok(HttpResponse::Ok().json(product_list))
}

async fn get_product_details(path: web::Path<i32>) -> Result<HttpResponse, ApiError> {
    let product_id = path.into_inner();
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Query product with likes count
    let product_row = client.query_one(
        r#"
        SELECT 
            p.id, 
            p.name, 
            p.category, 
            p.price, 
            p.default_image, 
            p.description,
            COUNT(pl.id) as likes_count
        FROM products p
        LEFT JOIN product_likes pl ON p.id = pl.product_id
        WHERE p.id = $1
        GROUP BY p.id
        "#,
        &[&product_id],
    ).await?;

    // Query colors
    let colors = client.query(
        "SELECT color_name as color, color_image as image FROM product_colors WHERE product_id = $1",
        &[&product_id],
    ).await?;

    // Query if liked (you'll need to pass user_id as parameter)
    // For now keeping it as false - implement this based on your auth system
    let liked = false;

    let product = Product {
        id: product_row.get(0),
        name: product_row.get(1),
        category: product_row.get(2),
        price: product_row.get(3),
        default_image: product_row.get::<_, Option<String>>(4).map(|img| {
            if img.starts_with("http") {
                img
            } else {
                format!("http://127.0.0.1:8080/uploads/products/{}", img)
            }
        }),
        description: product_row.get(5),
        liked: Some(liked),
        likes_count: product_row.get(6), // Add the likes count
    };

    let color_list: Vec<ProductColor> = colors
        .iter()
        .map(|row| ProductColor {
            color: row.get(0),
            image: row.get(1),
        })
        .collect();

    let response = ProductDetail {
        product,
        colors: color_list,
    };

    Ok(HttpResponse::Ok().json(response))
}

async fn get_all_product_colors() -> Result<HttpResponse, ApiError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let colors = client
        .query(
            "SELECT product_id, color_name as color, color_image as image FROM product_colors",
            &[],
        )
        .await?;

    let color_list: Vec<serde_json::Value> = colors
        .iter()
        .map(|row| {
            serde_json::json!({
                "product_id": row.get::<_, i32>(0),
                "color": row.get::<_, String>(1),
                "image": row.get::<_, String>(2),
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(color_list))
}

#[derive(Deserialize)]
struct LikeRequest {
    user_id: i32,
    product_id: i32,
}

async fn toggle_product_like(like_data: web::Json<LikeRequest>) -> Result<HttpResponse, ApiError> {
    let (mut client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Start transaction
    let transaction = client.transaction().await?;

    // Extract values into local variables
    let user_id = like_data.user_id;
    let product_id = like_data.product_id;

    // Check if like exists
    let existing_like = transaction
        .query_opt(
            "SELECT id FROM product_likes 
             WHERE user_id = $1 AND product_id = $2",
            &[&user_id, &product_id],
        )
        .await?;

    let is_liked = if existing_like.is_some() {
        // Unlike if exists
        transaction
            .execute(
                "DELETE FROM product_likes 
                 WHERE user_id = $1 AND product_id = $2",
                &[&user_id, &product_id],
            )
            .await?;
        false
    } else {
        // Like if doesn't exist
        transaction
            .execute(
                "INSERT INTO product_likes (user_id, product_id) 
                 VALUES ($1, $2)",
                &[&user_id, &product_id],
            )
            .await?;
        true
    };

    // Get updated likes count
    let likes_count = transaction
        .query_one(
            "SELECT COUNT(*) FROM product_likes 
             WHERE product_id = $1",
            &[&product_id],
        )
        .await?
        .get::<_, i64>(0);

    // Commit transaction
    transaction.commit().await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "is_liked": is_liked,
        "likes_count": likes_count
    })))
}
async fn get_user_likes(
    user_id: web::Path<i32>,
    web::Query(params): web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, ApiError> {
    let search_query = params.get("search").map(|s| s.to_lowercase());

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let query = match search_query {
        Some(query) if !query.is_empty() => {
            client
                .query(
                    "SELECT p.id, p.name, p.category, p.price, p.default_image 
                 FROM products p
                 JOIN product_likes pl ON p.id = pl.product_id
                 WHERE pl.user_id = $1 
                 AND LOWER(p.name) LIKE $2
                 ORDER BY p.id ASC",
                    &[&user_id.into_inner(), &format!("%{}%", query)],
                )
                .await?
        }
        _ => {
            client
                .query(
                    "SELECT p.id, p.name, p.category, p.price, p.default_image 
                 FROM products p
                 JOIN product_likes pl ON p.id = pl.product_id
                 WHERE pl.user_id = $1
                 ORDER BY p.id ASC",
                    &[&user_id.into_inner()],
                )
                .await?
        }
    };

    let products: Vec<Product> = query
        .iter()
        .map(|row| Product {
            id: row.get(0),
            name: row.get(1),
            category: row.get(2),
            price: row.get(3),
            default_image: row.get::<_, Option<String>>(4).map(|img| {
                if img.starts_with("http") {
                    img
                } else {
                    format!("http://127.0.0.1:8080/uploads/products/{}", img)
                }
            }),
            description: None, // Kolom description tidak diambil dari query
            liked: Some(true),
            likes_count: row.get(6),
        })
        .collect();

    Ok(HttpResponse::Ok().json(products))
}

// Update your existing structs and add new ones:



#[derive(Deserialize)]
struct VerifyCodeRequest {
    email: String,
    code: String,
}

#[derive(Deserialize)]
struct NewPasswordRequest {
    email: String,
    code: String,  // Include code in the final request for additional validation
    new_password: String,
    confirm_password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_to: Option<String>,
}

// Updated forgot password handler
// Di main.rs
#[derive(Deserialize)]
struct ForgotPasswordRequest {
    email: String,
}

#[derive(Serialize)]
struct ForgotPasswordResponse {
    success: bool,
    message: String,
    verification_code: Option<String>, // Kirim kode verifikasi ke frontend
}


async fn forgot_password(
    request: web::Json<ForgotPasswordRequest>,
) -> Result<HttpResponse, ApiError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // 1. Cek apakah email ada di database
    let user_exists = client.query_opt(
        "SELECT id FROM users WHERE email = $1", 
        &[&request.email]
    ).await?;

    if user_exists.is_none() {
        return Ok(HttpResponse::Ok().json(ForgotPasswordResponse {
            success: false,
            message: "If this email exists, a verification code has been sent".to_string(),
            verification_code: None,
        }));
    }

    // 2. Generate kode verifikasi 6 digit
    let verification_code = generate_6_digit_code();

    // 3. Simpan ke database dengan expiry time
    client.execute(
        "INSERT INTO password_reset_codes (email, code, expires_at) 
         VALUES ($1, $2, NOW() + INTERVAL '10 minutes')
         ON CONFLICT (email) 
         DO UPDATE SET code = EXCLUDED.code, expires_at = EXCLUDED.expires_at",
        &[&request.email, &verification_code],
    ).await?;

    // 4. Kirim email (implementasi ini sudah ada di kode Anda)
    send_forgot_password_email(&request.email, &verification_code).await?;

    Ok(HttpResponse::Ok().json(ForgotPasswordResponse {
        success: true,
        message: "Verification code sent".to_string(),
        verification_code: Some(verification_code), // Kirim kode ke frontend
    }))
}

#[derive(Deserialize)]
struct GetEmailByCodeRequest {
    code: String,
}

#[derive(Serialize)]
struct EmailResponse {
    email: String,
}

async fn get_email_by_code(
    request: web::Json<GetEmailByCodeRequest>,
) -> Result<HttpResponse, ApiError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Cari email berdasarkan kode verifikasi yang masih valid
    let row = client.query_one(
        "SELECT email FROM password_reset_codes 
         WHERE code = $1 AND expires_at > NOW()",
        &[&request.code],
    ).await?;

    let email: String = row.get(0);

    Ok(HttpResponse::Ok().json(EmailResponse { email }))
}

// Verification handler
async fn verify_reset_code(request: web::Json<VerifyCodeRequest>) -> Result<HttpResponse, ApiError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Verify code
    let valid = client.query_opt(
        "SELECT email FROM password_reset_codes 
         WHERE email = $1 AND code = $2 AND expires_at > NOW()",
        &[&request.email, &request.code],
    ).await?;

    if valid.is_none() {
        return Ok(HttpResponse::Ok().json(AuthResponse {
            success: false,
            message: "Invalid or expired verification code".to_string(),
            redirect_to: None,
        }));
    }

    Ok(HttpResponse::Ok().json(AuthResponse {
        success: true,
        message: "Verification successful".to_string(),
        redirect_to: Some("/newpassword".to_string()),
    }))
}

// New password handler
async fn set_new_password(request: web::Json<NewPasswordRequest>) -> Result<HttpResponse, ApiError> {
    // Validate passwords match
    if request.new_password != request.confirm_password {
        return Ok(HttpResponse::BadRequest().json(AuthResponse {
            success: false,
            message: "Passwords do not match".to_string(),
            redirect_to: None,
        }));
    }

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Verify code again (extra security)
    let valid = client.query_opt(
        "SELECT email FROM password_reset_codes 
         WHERE email = $1 AND code = $2 AND expires_at > NOW()",
        &[&request.email, &request.code],
    ).await?;

    if valid.is_none() {
        return Ok(HttpResponse::BadRequest().json(AuthResponse {
            success: false,
            message: "Session expired. Please start the process again".to_string(),
            redirect_to: Some("/forgot-password".to_string()),
        }));
    }

    // Hash new password
    let hashed_password = hash(&request.new_password, DEFAULT_COST)
        .map_err(|_| ApiError::ValidationError("Failed to hash password".to_string()))?;

    // Update password
    client.execute(
        "UPDATE users SET password = $1 WHERE email = $2",
        &[&hashed_password, &request.email],
    ).await?;

    // Clean up reset code
    client.execute(
        "DELETE FROM password_reset_codes WHERE email = $1",
        &[&request.email],
    ).await?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        success: true,
        message: "Password updated successfully".to_string(),
        redirect_to: Some("/login".to_string()),
    }))
}

// Helper function to generate 6-digit code
fn generate_6_digit_code() -> String {
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1_000_000))
}

// Email sending function
async fn send_forgot_password_email(email: &str, code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let email_message = Message::builder()
        .from("theyywearr@gmail.com".parse()?)
        .to(email.parse()?)
        .subject("Password Reset Verification Code")
        .body(format!(
            "You requested to reset your password.\n\n\
             Your verification code is: {}\n\n\
             This code will expire in 10 minutes.",
            code
        ))?;

    let creds = Credentials::new(
        "theyywearr@gmail.com".to_string(),
        "fdqakyyiwofdzixz".to_string(),
    );

    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(&email_message)?;
    Ok(())
}
#[derive(Deserialize)]
struct VerifyAndGetEmailRequest {
    code: String,
// 
}
#[derive(Serialize)]
struct AdminUser {
    id: i32,
    fullname: String,
    email: String,
    role: String,
    is_online: bool,
    last_activity: Option<String>,
}


async fn get_admin_users() -> Result<HttpResponse, ApiError> {
    // Connect to database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Query all users with their details
    let rows = client.query(
        "SELECT id, fullname, email, role, is_online, last_activity 
         FROM users 
         WHERE role = 'admin'
         ORDER BY last_activity DESC",
        &[],
    ).await?;

    let users: Vec<AdminUser> = rows.iter().map(|row| {
        AdminUser {
            id: row.get(0),
            fullname: row.get(1),
            email: row.get(2),
            role: row.get(3),
            is_online: row.get(4),
            last_activity: row.get::<_, Option<NaiveDateTime>>(5)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string()),
        }
    }).collect();

    Ok(HttpResponse::Ok().json(users))
}

async fn verify_and_get_email(
    request: web::Json<VerifyAndGetEmailRequest>,
) -> Result<HttpResponse, ApiError> {
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Verifikasi kode dan dapatkan email
    let row = client.query_one(
        "SELECT email FROM password_reset_codes 
         WHERE code = $1 AND expires_at > NOW()",
        &[&request.code],
    ).await?;

    let email: String = row.get(0);

    Ok(HttpResponse::Ok().json(json!({
        "email": email,
        "valid": true
    })))
}

#[derive(Serialize)]
struct CurrentUserResponse {
    id: i32,
    fullname: String,
    email: String,
    role: String,
    img: Option<String>,
    is_online: bool,
}

// Add this route handler
async fn get_current_user(
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, ApiError> {
    // Extract user ID from headers or token (you'll need to implement this)
    // For now, I'll assume you're passing user_id as a header
    let user_id = req.headers().get("x-user-id")
        .ok_or(ApiError::ValidationError("User ID not provided".to_string()))?
        .to_str()
        .map_err(|_| ApiError::ValidationError("Invalid user ID".to_string()))?
        .parse::<i32>()
        .map_err(|_| ApiError::ValidationError("Invalid user ID".to_string()))?;

    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let row = client.query_one(
        "SELECT id, fullname, email, role, img, is_online FROM users WHERE id = $1",
        &[&user_id],
    ).await?;

    let user = CurrentUserResponse {
        id: row.get(0),
        fullname: row.get(1),
        email: row.get(2),
        role: row.get(3),
        img: row.get(4),
        is_online: row.get(5),
    };

    Ok(HttpResponse::Ok().json(user))
}
#[actix_web::main] // Di main.rs atau lib.rs
async fn main() -> std::io::Result<()> {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 menit
        loop {
            interval.tick().await;
            if let Err(e) = deactivate_inactive_users().await {
                eprintln!("Error checking inactive users: {}", e);
            }
        }
    });
    let cors = Cors::default()
        .allow_any_origin()
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
        .allowed_headers(vec![AUTHORIZATION, ACCEPT, CONTENT_TYPE])
        .max_age(3600);
    // Create users table if it doesn't exist
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Failed to connect to database: {}", e);
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Database connection failed")
    })?;

    // Handle connection in background
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Start HTTP server
    HttpServer::new(|| {
        App::new()
            .wrap(Cors::permissive())
            .service(web::resource("/uploads/{filename:.*}").route(web::get().to(serve_image)))
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/users", web::get().to(get_users))
            .route("/users/{id}", web::put().to(edit_user))
            .route("/verifyotp", web::post().to(verify_otp))
            .route("/user/{id}", web::get().to(get_user_by_id))
            .route("/profile", web::post().to(get_profile))
            .route("/admin/users", web::get().to(get_admin_users))
            .route("/api/current-user", web::get().to(get_current_user))
            .route(
                "/user/{user_id}/order/{order_id}",
                web::get().to(get_order_details),
            )
            .route(
                "/user/{user_id}/order/{order_id}/notes",
                web::put().to(update_order_notes),
            )
            .route(
                "/profile/{id}/upload",
                web::post().to(upload_profile_picture),
            )
            .route("/check_activity", web::get().to(check_activity))
            .route("/user/{id}/activity", web::post().to(update_activity))
            .route("/online-users", web::get().to(get_online_users))
            .route("/logout", web::post().to(logout))
            .route(
                "/user/{user_id}/addresses",
                web::get().to(get_user_addresses),
            )
            .route(
                "/user/{user_id}/address", // Add this line to support singular
                web::post().to(add_address),
            )
            .route("/get-email-by-code", web::post().to(get_email_by_code))
            .route("/verify-and-get-email", web::post().to(verify_and_get_email))
            .route(
                "/user/{user_id}/addresses", // Keep this existing line
                web::post().to(add_address),
            )
            .route(
                "/user/{user_id}/address/default", // Keep this existing line
                web::post().to(add_address),
            )
            .route(
                "/user/{user_id}/address/{address_id}",
                web::put().to(update_address),
            )
            .route(
                "/user/{user_id}/address/{address_id}",
                web::delete().to(delete_address),
            )
            .route(
                "/user/{user_id}/address/default",
                web::get().to(get_default_address),
            )
            .route("/user/{user_id}/orders", web::get().to(get_user_orders))
            .route("/user/{user_id}/order", web::post().to(create_order))
            .route("/api/products", web::post().to(add_product))
            .route("/api/products/{id}", web::put().to(update_product))
            .route("/api/products/{id}", web::delete().to(delete_product))
            .route(
                "/api/products/{id}/colors",
                web::post().to(update_product_colors),
            )
            .route("/api/products", web::get().to(get_products))
            .route("/api/products/{id}", web::get().to(get_product_details))
            .route("/api/products/upload", web::post().to(upload_product_image))
            .route("/api/product-colors", web::get().to(get_all_product_colors))
            .route("/api/products/like", web::post().to(toggle_product_like))
            .route("/user/{user_id}/likes", web::get().to(get_user_likes))
            // Add these routes to your HttpServer::new() configuration
            .route("/user/{user_id}/cart", web::get().to(get_cart_items))
            .route("/user/{user_id}/cart", web::post().to(add_to_cart))
            .route(
                "/user/{user_id}/cart/{item_id}",
                web::put().to(update_cart_item),
            )
            .route(
                "/user/{user_id}/cart/{item_id}",
                web::delete().to(remove_cart_item),
            )
            .route("/user/{user_id}/cart/clear", web::delete().to(clear_cart))
            .route("/user/{user_id}/cart/count", web::get().to(get_cart_count))
            .route("/check-admin", web::post().to(check_admin))
            // In your main() function where you configure routes:
.route("/forgot-password", web::post().to(forgot_password))
.route("/forgot-password/verify", web::post().to(verify_reset_code))
.route("/reset-password", web::post().to(set_new_password))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

