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
                bat 'docker build -t soc-app .'
            }
        }

        stage('Stop Old Container') {
            steps {
                bat 'docker rm -f soc-container || exit 0'
            }
        }

        stage('Run New Container') {
            steps {
                bat 'docker run -d -p 5000:5000 --name soc-container soc-app'
            }
        }
    }
}