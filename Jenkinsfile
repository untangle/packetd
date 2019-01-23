void buildPacketd(String libc, String buildDir) {
  sh "docker pull untangleinc/packetd:build-${libc}"
  sh "docker-compose -f ${buildDir}/build/docker-compose.build.yml -p packetd_${libc} run ${libc}"
  sh "cp ${buildDir}/cmd/packetd/packetd cmd/packetd/packetd-${libc}"
  sh "cp ${buildDir}/cmd/settingsd/settingsd cmd/settingsd/settingsd-${libc}"
}

void archivePacketd() {
  archiveArtifacts artifacts:"cmd/packetd/packetd-*,cmd/settingsd/settingsd-*", fingerprint: true
}

pipeline {
  agent none

  stages {
    stage('Build') {

      parallel {
        stage('Build musl') {
	  agent { label 'mfw' }

          environment {
            libc = 'musl'
            buildDir = "${env.HOME}/build-packetd-${env.BRANCH_NAME}-${libc}/go/src/github.com/untangle/packetd"
          }

	  stages {
            stage('Prep WS musl') {
              steps { dir(buildDir) { checkout scm } }
            }

            stage('Build packetd musl') {
              steps {
                buildPacketd(libc, buildDir)
                stash(name:"packetd-${libc}", includes:"cmd/packetd/packetd-*,cmd/settingsd/settingsd-*")
              }
            }
          }

          post {
            success { archivePacketd() }
          }
        }

        stage('Build glibc') {
	  agent { label 'mfw' }

          environment {
            libc = 'glibc'
            buildDir = "${env.HOME}/build-packetd-${env.BRANCH_NAME}-${libc}/go/src/github.com/untangle/packetd"
          }

	  stages {
            stage('Prep WS glibc') {
              steps { dir(buildDir) { checkout scm } }
            }

            stage('Build packetd glibc') {
              steps {
                buildPacketd(libc, buildDir)
                stash(name:"packetd-${libc}", includes:"cmd/packetd/packetd-*,cmd/settingsd/settingsd-*")
              }
            }
          }

          post {
            success { archivePacketd() }
          }
        }
      }
    }

    stage('Test') {
      parallel {
        stage('Test musl') {
	  agent { label 'mfw' }

          environment {
            libc = 'musl'
	    packetd = "cmd/packetd/packetd-${libc}"
	    settingsd = "cmd/settingsd/settingsd-${libc}"
          }

          stages {
            stage('Prep musl') {
              steps {
                unstash(name:"packetd-${libc}")
                sh("test -f ${packetd} && file ${packetd} | grep -q -v GNU/Linux")
                sh("test -f ${settingsd} && file ${settingsd} | grep -q -v GNU/Linux")
              }
            }
          }
        }

        stage('Test libc') {
	  agent { label 'mfw' }

          environment {
            libc = 'glibc'
	    packetd = "cmd/packetd/packetd-${libc}"
	    settingsd = "cmd/settingsd/settingsd-${libc}"
          }

          stages {
            stage('Prep libc') {
              steps {
                unstash(name:"packetd-${libc}")
                sh("test -f ${packetd} && file ${packetd} | grep -q GNU/Linux")
                sh("test -f ${settingsd} && file ${settingsd} | grep -q GNU/Linux")
              }
            }
          }
        }
      }

      post {
	always {
	  script {
	    // set result before pipeline ends, so emailer sees it
	    currentBuild.result = currentBuild.currentResult
          }
          emailext(to:'seb@untangle.com', subject:"${env.JOB_NAME} #${env.BUILD_NUMBER}: ${currentBuild.result}", body:"${env.BUILD_URL}")
          slackSend(channel:"@Seb", message:"${env.JOB_NAME} #${env.BUILD_NUMBER}: ${currentBuild.result} at ${env.BUILD_URL}")
	}
	changed {
	  script {
	    // set result before pipeline ends, so emailer sees it
	    currentBuild.result = currentBuild.currentResult
          }
          emailext(to:'nfgw-engineering@untangle.com', subject:"${env.JOB_NAME} #${env.BUILD_NUMBER}: ${currentBuild.result}", body:"${env.BUILD_URL}")
          slackSend(channel:"#engineering", message:"${env.JOB_NAME} #${env.BUILD_NUMBER}: ${currentBuild.result} at ${env.BUILD_URL}")
	}
      }
    }
  }
}
