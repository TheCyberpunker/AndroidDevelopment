package com.bps.firstapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) { //onCreate method for main activity
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void changeImage(View view) { //create a method with the name changeImage
        // ImageView: name of the object, predefine by java
        // imageView: name of the image view
        // Button: name of the object
        // button: name of the button view
        ImageView imageView = (ImageView) findViewById(R.id.imageView);
        Button button = findViewById(R.id.buttonChanger);

        imageView.setImageResource(R.drawable.wall);
    }
}