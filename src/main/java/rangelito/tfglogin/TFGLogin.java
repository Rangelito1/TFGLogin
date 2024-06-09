package rangelito.tfglogin;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.io.File;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class TFGLogin extends JavaPlugin {

    private Connection connection;
    private Connection sqliteConnection;
    private ScheduledExecutorService scheduler;
    private long lastModified;

    @Override
    public void onEnable() {
        // Inicialización de lastModified con el valor actual de la última modificación del archivo authme.db
        File authmeDb = new File(getDataFolder().getParentFile(), "AuthMe/authme.db");
        lastModified = authmeDb.lastModified();

        // Lógica de inicio del plugin
        System.out.println("TFGLogin ha sido habilitado.");

        // Intenta establecer conexión con la base de datos MySQL
        try {
            connection = DriverManager.getConnection("none", "none", "none");
            // Intenta establecer conexión con la base de datos SQLite
            String sqliteUrl = "jdbc:sqlite:" + authmeDb.getAbsolutePath();
            sqliteConnection = DriverManager.getConnection(sqliteUrl);
            System.out.println("Archivo AuthMe encontrado.");
        } catch (SQLException e) {
            System.out.println("Error al acceder a las bases de datos.");
            e.printStackTrace();
            return;  // Si no podemos conectar, no tiene sentido continuar.
        }

        // Verifica que las conexiones no sean nulas
        if (connection != null && sqliteConnection != null) {
            System.out.println("Conexiones a las bases de datos establecidas correctamente.");
            replicateData();  // Replicar datos al iniciar
        } else {
            System.out.println("No se pudo establecer las conexiones a las bases de datos.");
        }

        // Configura el programador para verificar actualizaciones
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(this::checkForUpdates, 0, 1, TimeUnit.MINUTES);

        // Programa la transferencia de la carpeta playerdata cada minuto
        scheduler.scheduleAtFixedRate(this::transferPlayerData, 0, 1, TimeUnit.MINUTES);
    }

    private void checkForUpdates() {
        // Manejo de excepciones en el método checkForUpdates
        try {
            File authmeDb = new File(getDataFolder().getParentFile(), "AuthMe/authme.db");
            if (authmeDb.lastModified() > lastModified) {
                lastModified = authmeDb.lastModified();
                replicateData();  // El archivo ha sido modificado, replicar los datos
            }
        } catch (Exception e) {
            System.out.println("Error al verificar actualizaciones en el archivo AuthMe.");
            e.printStackTrace();
        }
    }

    private void replicateData() {
        System.out.println("Iniciando replicación de datos.");
        // Utiliza try-with-resources para el cierre automático de recursos
        try (Statement statement = sqliteConnection.createStatement();
             ResultSet resultSet = statement.executeQuery("SELECT realname, password FROM authme")) {

            while (resultSet.next()) {
                String realname = resultSet.getString("realname");
                String password = resultSet.getString("password");

                System.out.println("Replicando usuario: " + realname);

                // Verifica si el usuario ya existe en la base de datos MySQL
                try (PreparedStatement checkStatement = connection.prepareStatement("SELECT * FROM usuarios WHERE usuario = ?")) {
                    checkStatement.setString(1, realname);
                    try (ResultSet mysqlResultSet = checkStatement.executeQuery()) {
                        if (mysqlResultSet.next()) {
                            // Actualiza la clave si el usuario ya existe
                            try (PreparedStatement updateStatement = connection.prepareStatement("UPDATE usuarios SET clave = ? WHERE usuario = ?")) {
                                updateStatement.setString(1, password);
                                updateStatement.setString(2, realname);
                                updateStatement.executeUpdate();
                            }
                        } else {
                            // Inserta un nuevo usuario si no existe
                            try (PreparedStatement insertStatement = connection.prepareStatement("INSERT INTO usuarios (usuario, clave) VALUES (?, ?)")) {
                                insertStatement.setString(1, realname);
                                insertStatement.setString(2, password);
                                insertStatement.executeUpdate();
                            }
                        }
                    }
                }
            }
            System.out.println("Replicación de datos completada.");
        } catch (SQLException e) {
            System.out.println("Error al replicar datos.");
            e.printStackTrace();
        }
    }

    private void transferPlayerData() {
        File playerDataFolder = new File("Spawn/playerdata");
        String remoteServer = "opc@158.179.222.248:/home/opc/html/wp-content/uploads";
        String keyFile = "plugins/TFGLogin/key.key";

        // Construir el comando SCP
        String scpCommand = String.format("scp -i %s -r %s %s", keyFile, playerDataFolder.getAbsolutePath(), remoteServer);

        try {
            // Ejecutar el comando SCP
            System.out.println("Ejecutando comando SCP: " + scpCommand);
            Process process = Runtime.getRuntime().exec(scpCommand);

            // Leer la salida y errores del proceso
            try (BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
                 BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {

                String s;
                System.out.println("Salida estándar del comando SCP:");
                while ((s = stdInput.readLine()) != null) {
                    System.out.println(s);
                }

                System.out.println("Salida de error del comando SCP:");
                while ((s = stdError.readLine()) != null) {
                    System.out.println(s);
                }
            }

            int exitCode = process.waitFor();
            System.out.println("Código de salida: " + exitCode);
            if (exitCode == 0) {
                System.out.println("Transferencia de carpeta playerdata exitosa.");
            } else {
                System.out.println("Error en la transferencia de carpeta playerdata. Código de salida: " + exitCode);
            }
        } catch (IOException | InterruptedException e) {
            System.out.println("Error al ejecutar el comando SCP.");
            e.printStackTrace();
        }
    }

    @Override
    public void onDisable() {
        // Detener el scheduler
        if (scheduler != null) {
            scheduler.shutdown();
        }

        System.out.println("TFGLogin ha sido deshabilitado.");
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (cmd.getName().equalsIgnoreCase("PageLogin")) {
            if (sender instanceof Player) {
                Player player = (Player) sender;
                if (args.length > 0) {
                    String password = args[0];
                    player.sendMessage("Comando ejecutado por " + player.getName() + ". Contraseña elegida: " + password);

                    try {
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
                        String encodedPassword = bytesToHex(hash);

                        PreparedStatement checkStatement = connection.prepareStatement("SELECT * FROM usuarios WHERE usuario = ?");
                        checkStatement.setString(1, player.getName());
                        ResultSet resultSet = checkStatement.executeQuery();

                        if (resultSet.next()) {
                            player.sendMessage("¡Ya estás registrado!");
                        } else {
                            PreparedStatement statement = connection.prepareStatement("INSERT INTO usuarios (usuario, clave) VALUES (?, ?)");
                            statement.setString(1, player.getName());
                            statement.setString(2, encodedPassword);
                            statement.executeUpdate();
                        }
                    } catch (SQLException | NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }

                    return true;
                } else {
                    player.sendMessage("Por favor, introduce una contraseña.");
                    return false;
                }
            } else {
                sender.sendMessage("Este comando solo puede ser ejecutado por un jugador.");
                return false;
            }
        }
        return false;
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}