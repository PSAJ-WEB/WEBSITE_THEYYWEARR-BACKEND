use actix_web::{web, App, HttpServer, HttpResponse, Error as ActixError};
use serde::{Serialize, Deserialize};
use tokio_postgres::{NoTls, Error};
use bcrypt::{hash, verify, DEFAULT_COST};
use actix_cors::Cors;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use rand::Rng;


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
            return Ok(HttpResponse::InternalServerError().json("Failed to send verification email"));
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
        Ok(_) => Ok(HttpResponse::Created().json("User registered. Please check your email for verification code.")),
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
    ).await.map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Get user from database
    let statement = client.prepare(
        "SELECT fullname, password FROM users WHERE email = $1"
    ).await.map_err(|e| {
        eprintln!("Prepare statement error: {}", e);
        actix_web::error::ErrorInternalServerError("Database statement preparation error")
    })?;

    match client.query_opt(&statement, &[&credentials.email]).await {
        Ok(Some(row)) => {
            let stored_password: String = row.get(1);
            let fullname: String = row.get(0);

            match verify(&credentials.password, &stored_password) {
                Ok(valid) => {
                    if valid {
                        Ok(HttpResponse::Ok().json(LoginResponse {
                            message: "Login successful".to_string(),
                            fullname
                        }))
                    } else {
                        Ok(HttpResponse::Unauthorized().json(LoginResponse {
                            message: "Invalid credentials".to_string(),
                            fullname: String::new()
                        }))
                    }
                }
                Err(_) => Ok(HttpResponse::InternalServerError().json(LoginResponse {
                    message: "Error verifying password".to_string(),
                    fullname: String::new()
                }))
            }
        }
        Ok(None) => Ok(HttpResponse::Unauthorized().json(LoginResponse {
            message: "User not found".to_string(),
            fullname: String::new()
        })),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json(LoginResponse {
                message: "Database error".to_string(),
                fullname: String::new()
            }))
        }
    }
}

// Struct untuk response data user
#[derive(Serialize)]
struct User {
    id: i32,
    fullname: String,
    email: String,
    password: String,
}

// Handler untuk mendapatkan semua user
async fn get_users() -> Result<HttpResponse, ActixError> {
    // Koneksi ke database
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    ).await.map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Query untuk mendapatkan semua user
    let statement = client.prepare("SELECT id, fullname, email, password FROM users").await.map_err(|e| {
        eprintln!("Prepare statement error: {}", e);
        actix_web::error::ErrorInternalServerError("Database statement preparation error")
    })?;

    let rows = client.query(&statement, &[]).await.map_err(|e| {
        eprintln!("Query error: {}", e);
        actix_web::error::ErrorInternalServerError("Database query error")
    })?;

    // Mapping hasil query ke struct User
    let users: Vec<User> = rows.iter().map(|row| User {
        id: row.get(0),
        fullname: row.get(1),
        email: row.get(2),
        password: row.get(3),
    }).collect();

    Ok(HttpResponse::Ok().json(users))
}

#[derive(Deserialize)]
struct UpdateUser {
    fullname: Option<String>,
    email: Option<String>,
    password: Option<String>,
}

async fn edit_user(
    path: web::Path<i32>, // Mendapatkan ID pengguna dari URL
    update_data: web::Json<UpdateUser>,
) -> Result<HttpResponse, ActixError> {
    let user_id = path.into_inner(); // Mengambil ID pengguna dari path

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

    // Periksa apakah pengguna dengan ID tersebut ada
    let user_exists = client
        .query_one("SELECT COUNT(*) FROM users WHERE id = $1", &[&user_id])
        .await
        .map_err(|e| {
            eprintln!("Error checking user existence: {}", e);
            actix_web::error::ErrorInternalServerError("Database query error")
        })?;
    let count: i64 = user_exists.get(0);
    if count == 0 {
        return Ok(HttpResponse::NotFound().json(RegisterResponse {
            message: "User not found".to_string(),
        }));
    }

    // Siapkan query untuk memperbarui data pengguna
    let mut updates = Vec::new();
    let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new(); // Corrected type
    let mut param_index = 1;

    // Update fullname jika ada
    if let Some(fullname) = &update_data.fullname {
        updates.push(format!("fullname = ${}", param_index));
        params.push(fullname); // Push &str
        param_index += 1;
    }

    // Update email jika ada
    if let Some(email) = &update_data.email {
        // Periksa apakah email sudah digunakan oleh pengguna lain
        let email_check = client
            .query_one("SELECT COUNT(*) FROM users WHERE email = $1 AND id != $2", &[&email, &user_id])
            .await
            .map_err(|e| {
                eprintln!("Error checking email: {}", e);
                actix_web::error::ErrorInternalServerError("Database query error")
            })?;
        let email_count: i64 = email_check.get(0);
        if email_count > 0 {
            return Ok(HttpResponse::Conflict().json(RegisterResponse {
                message: "Email already registered by another user".to_string(),
            }));
        }

        updates.push(format!("email = ${}", param_index));
        params.push(email); // Push &str
        param_index += 1;
    }

    // Update password jika ada
    if let Some(password) = &update_data.password {
        // Hash password baru
        let hashed_password = match hash(password, DEFAULT_COST) {
            Ok(hp) => hp,
            Err(_) => {
                return Ok(HttpResponse::InternalServerError().json(RegisterResponse {
                    message: "Error hashing password".to_string(),
                }))
            }
        };

        updates.push(format!("password = ${}", param_index));
        params.push(Box::leak(Box::new(hashed_password)) as &(dyn tokio_postgres::types::ToSql + Sync));
        param_index += 1;
    }

    // Jika tidak ada field yang diperbarui, kembalikan pesan kesalahan
    if updates.is_empty() {
        return Ok(HttpResponse::BadRequest().json(RegisterResponse {
            message: "No fields to update".to_string(),
        }));
    }

    // Buat query UPDATE
    let query = format!(
        "UPDATE users SET {} WHERE id = ${}",
        updates.join(", "),
        param_index
    );
    params.push(&user_id); // Push &i32

    // Jalankan query
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
        .from("eridayalma999@gmail.com".parse()?)
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
        "eridayalma999@gmail.com".to_string(),
        "qqzjftjsxmlqxgul".to_string()
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
                    actix_web::error::ErrorInternalServerError("Failed to update verification status")
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Create users table if it doesn't exist
    let (client, connection) = tokio_postgres::connect(
        "postgres://postgres:erida999@localhost:5432/postgres",
        NoTls,
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Start HTTP server
    HttpServer::new(|| {
        App::new()
            .wrap(Cors::permissive())
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/users", web::get().to(get_users))
            .route("/users/{id}", web::put().to(edit_user)) 
            .route("/verifyotp", web::post().to(verify_otp)) 
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}