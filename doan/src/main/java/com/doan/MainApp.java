package com.doan;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class MainApp extends Application {
    @Override
    public void start(Stage stage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("/main_view.fxml")); // lưu ý có dấu "/"
        stage.setScene(new Scene(root));
        stage.setTitle("Client Subdomain Scanner");
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
