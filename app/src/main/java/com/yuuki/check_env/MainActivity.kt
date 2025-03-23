package com.yuuki.check_env

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import kotlin.system.exitProcess

class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val text = findViewById<TextView>(R.id.res_show)
        val refresh = findViewById<Button>(R.id.refresh)

        refresh.setOnClickListener{
            text.text = is_env_abnormal();
        }
    }


    external fun is_env_abnormal(): String

    companion object {
        init {
            System.loadLibrary("check_env")
        }
    }
}