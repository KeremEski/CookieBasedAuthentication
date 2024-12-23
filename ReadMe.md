# Cookie Based Authentication Project

This project demonstrates how to implement cookie-based authentication using ASP.NET Core.

## Getting Started

These instructions will help you get your project up and running on your local machine.

### Prerequisites

- .NET Core SDK
- Visual Studio or Visual Studio Code
- SQL Server or another database server

### Installation

1. Clone this project:
    ```sh
    git clone https://github.com/KeremEski/CookieBasedAuthentication.git
    cd CookieBasedAuthentication
    ```

2. Install the required packages:
    ```sh
    dotnet restore
    ```

3. Configure the database connection:
    Open the `appsettings.json` file and update the `ConnectionStrings` section with your own database information.
    ```json
    {
      "ConnectionStrings": {
        "DefaultConnection": "Server=YOUR_SERVER;Database=YOUR_DATABASE;User Id=YOUR_USERNAME;Password=YOUR_PASSWORD;"
      }
    }
    ```

4. Create the migration:
    ```sh
    dotnet ef migrations add InitialCreate
    ```

5. Update the database:
    ```sh
    dotnet ef database update
    ```

6. Run the application:
    ```sh
    dotnet run
    ```

### Usage

Once the application is running, you can use it by navigating to `https://localhost:5062` in your browser.

### Important Settings

- Update the database connection information in the `appsettings.json` file according to your environment.
- Configure authentication and authorization settings in the `Startup.cs` file.
- Configure cookie settings in the `ConfigureServices` method in the `Startup.cs` file.

### Customizable Points

- **Database Connection**: Update the `DefaultConnection` setting in the `appsettings.json` file with your own database information.
- **Authentication Settings**: Customize the authentication settings in the `ConfigureServices` method in the `Startup.cs` file.
- **Cookie Settings**: Customize the cookie settings in the `ConfigureServices` method in the `Startup.cs` file.

### Important Points and Explanations

#### AuthService

The `AuthService` class is responsible for handling authentication logic. It includes methods for user login, logout, and user validation. The main purpose of this service is to encapsulate the authentication logic and make it reusable across the application.

#### AccountController

The `AccountController` handles HTTP requests related to user accounts, such as login and logout. It interacts with the `AuthService` to perform authentication operations. Here is a brief explanation of the key actions:

- **Login**: This action handles user login requests. It validates the user credentials and, if valid, creates an authentication cookie.
- **Logout**: This action handles user logout requests. It removes the authentication cookie and redirects the user to the login page.

## Contributing

If you want to contribute, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License. For more information, see the `LICENSE` file.
