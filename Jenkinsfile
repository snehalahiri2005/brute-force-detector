pipeline {
    agent any

    stages {
        stage('Clone Code') {
            steps {
                git branch: 'main', url: 'https://github.com/snehalahiri2005/brute-force-detector.git'
            }
        }

        stage('Build Docker Image') {
            steps {
                bat 'docker build -t brute-force-app .'
            }
        }

        stage('Stop Old Container') {
            steps {
                bat 'docker stop brute-force-app || exit 0'
                bat 'docker rm brute-force-app || exit 0'
            }
        }

        stage('Run New Container') {
            steps {
                bat 'docker run -d -p 5000:5000 --name brute-force-app brute-force-app'
            }
        }
    }
}