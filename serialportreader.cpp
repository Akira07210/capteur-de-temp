#include "serialportreader.h"
#include <QtEndian>
#include <QCoreApplication>


QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
QSqlQuery query;

SerialPortReader::SerialPortReader(QSerialPort *serialPort, QObject *parent) :
    QObject(parent),
    m_serialPort(serialPort),
    m_standardOutput(stdout)
{
    connect(m_serialPort, &QSerialPort::readyRead, this, &SerialPortReader::handleReadyRead);
    connect(m_serialPort, &QSerialPort::errorOccurred, this, &SerialPortReader::handleError);
    //connect(&m_timer, &QTimer::timeout, this, &SerialPortReader::handleTimeout);


}

void SerialPortReader::handleReadyRead()
{
    //---------------------------------------------------------------------------
    //-------------------------  DECLARATION DES VARIABLE -----------------------
    //---------------------------------------------------------------------------
    // Clée de déchiffrement
    uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
    // Struture pour AES
    struct AES_ctx ctx;// Création de la structure
    // Je définit le contexte mais sans l'iv // Doit etre fait dans une fonction et non en global
    AES_init_ctx(&ctx,key);
    // Variable utilisée pour localiser les tetes dans le buffer
    int position_head = 0;
    // Taille de trame sans la tete
    int trame_taille = 24;
    // Tete passé en Hex pour rechercher dans les buffers
    QByteArray head = QByteArray::fromHex("aa55aa55");
    // Variable utilisée pour stocker la trame
    QByteArray trame , init_vector;
    // Variable utilisé pour noter l'état de la trame
    bool trame_valide = true;
    // Variables de stockage de données
    quint32 timestamp, node_id, frame_conteur ;
    quint16 humi,node_id2,temp,co2;
    quint8 pile,air,frame_type, len;


    //---------------------------------------------------------------------------
    //--------------------------  LECTURE ET TRAITEMENT  ------------------------
    //---------------------------------------------------------------------------

    // Lecture des donnés reçu sur le port
    m_readData.append(m_serialPort->readAll());

    // Je set position_head à la position de la première tete
    position_head = m_readData.indexOf(head,0);

    // Je récupère la trame sans la tete
    trame = m_readData.mid(position_head+4,trame_taille);

    //----------------------------------------------------------------------------
    //-------------------------- TRAITEMENT DE LA TRAME --------------------------
    //----------------------------------------------------------------------------

    if (trame.indexOf(head,0) == -1 && trame.length()==24)
    // ON NE TROUVE PAS DE TETE DONC LA TRAME EST BONNE
    {
        if(qFromLittleEndian<quint32>(trame.mid(4,4))!=qFromLittleEndian<quint16>(trame.mid(12,2)))
        // LES DEUX NODE_ID NE SONT PAS LES MEMES, LA TRAME EST DONC SOIT CHIFFRE SOIT FAUSSE
        {
            // Trame sous forme int avec -8 car seul le payload est chiffré
            uint8_t trame_uint8_t[trame_taille-8];
            // Variable en int utilisée pour l'iv du contexte
            uint8_t IV[16] ;
            // Je récupère l'init vector
            QByteArray Init_vector =trame.mid(0,4)+trame.mid(4,4) + trame.mid(0,4)+trame.mid(4,4);

            // Transfert dans le tableau int IV
            for(int i = 0; i<16; i++)
                IV[i] = Init_vector.at(i);

            // J'initialise l'IV du contexte
            AES_ctx_set_iv(&ctx,IV);

            // Je passe le payload en uint8_t
            for(int i = 8; i<24; i++)
                trame_uint8_t[i-8] = trame.at(i);


            // La fonction déchiffrer attend un multiple de 16 et le payload fait pile 16 donc pas de paddind
            // Déchiffrage de la trame
            AES_CBC_decrypt_buffer(&ctx,trame_uint8_t,16);

            // Repassage en Qbyte Array pour manier plus simplement les donnés
            for(int i = 8; i<24; i++){
                trame[i] = trame_uint8_t[i-8];
                //qDebug()<<"Qbyte Array : "<<QString::number(trame.at(i) ,16)<<"  uint8 : "<< QString::number(trame_uint8_t[i-8],16);
            }

            if(qFromLittleEndian<quint32>(trame.mid(4,4))!=qFromLittleEndian<quint16>(trame.mid(12,2)))
            {// Malgré le déchiffrement les deux node ID ne sont pas le meme
                trame_valide = false;
                qDebug()<<"Trame déchiffré mais reste fausse";

            }
}

        // Supprimer du début du buffer jusqu'à la fin de la trame
        m_readData.remove(0,28+position_head);
    }
    else if(trame.indexOf(head,0) != -1 &&trame.length()==24)
    // Cas ou on trouve une tete dans la trame
    {
        qDebug()<< "trame fausse : "<<trame.toHex();
        // J'incrémente la position jusqu'à la prochaine tete
        position_head += trame.indexOf(head,0);
        //Supprimer seulement jusqu à la prochaine tete
        m_readData.remove(0,position_head);
        trame_valide= false;
        // ATTENTION si deux tetes s'enchainent le programme crée un cas boquant => à corriger
    }

    //---------------------------------------------------------------------------
    //--------------------------- AFFICHAGE DES DONNES --------------------------
    //---------------------------------------------------------------------------
    if(trame_valide && trame.length()==24)
    {
        // Extraction des donnnés
        timestamp = qFromLittleEndian<quint32>(trame.mid(0,4));
        node_id = qFromLittleEndian<quint32>(trame.mid(4,4));
        frame_conteur = qFromLittleEndian<quint32>(trame.mid(8,4));
        node_id2 = qFromLittleEndian<quint16>(trame.mid(12,2));
        len = trame[14];
        frame_type = trame[15];
        temp = qFromLittleEndian<quint16>(trame.mid(16,2));
        humi = qFromLittleEndian<quint16>(trame.mid(18,2));
        pile = trame[20];
        air = trame[21];
        co2 = qFromLittleEndian<quint16>(trame.mid(22,2));

        qDebug()<<"Trame : "<<trame.toHex();

        qDebug()<<" timestamp : "<< timestamp<<" node_id : "<<node_id<<" node_id2 : "<<node_id2<<" frame_conteur:"<<frame_conteur<<" len : "<<len<<\
            " frame_type : "<<frame_type<<" temp : "<<(float)(qint16)temp/100<<" humi:"<<(float)humi/100<<"pile : "<<(float)pile/100<<" air : "<<air <<" co2 : "<<co2;

        //---------------------------------------------------------------------------
        //------------------------------- TAB DE DONNEE -----------------------------
        //---------------------------------------------------------------------------

        // Variable pour le dernier frame counter
        int last_frame_counter;

        // Récupération du timestamp mondial
        std::time_t t = std::time(0);

        // Creation du fichier ou ouverture
        db.setDatabaseName("/home/APOLLO2/fayolle/Bureau/bridge/bridge/creaderasync/bdy.db");
        // Connection à la base
        if(!db.open())qDebug()<<"Mauvais chemin";

        // Creation de la table si elle existe pas
        query.exec("CREATE TABLE \"data_from_capteur\" (\"id\"INTEGER,\"frame_counter\"INTEGER,\"timestamp\"INTEGER,\"temp\"NUMERIC,\"humi\"NUMERIC,\"co2\"	INTEGER,\"air\"INTEGER);");

        // Récupère le dernier frame counter en fonction du node id
        query.clear();
        QString test = "SELECT frame_counter FROM data_from_capteur WHERE id="; test += QString::number(node_id);
        if(!query.exec(test))
        {
            qDebug()<<"Pas de récupération du dernier frame counter";
            last_frame_counter = 0;
        }
        else {query.last(); last_frame_counter = query.value(0).toInt();}
        query.clear();

        if(last_frame_counter<(int)frame_conteur)
        {
            // Preparation de la commande
            query.prepare("INSERT INTO data_from_capteur (id,frame_counter,timestamp,temp,humi,co2,air)"
                         "VALUES (:id,:frame_counter,:timestamp,:temp,:humi,:co2,:air)");

            query.bindValue(":id", node_id);
            query.bindValue(":frame_counter", frame_conteur);
            query.bindValue(":temp", (float)(qint16)temp/100);
            query.bindValue(":humi", (float)humi/100);
            query.bindValue(":co2", co2);
            query.bindValue(":air", air);
            query.bindValue(":timestamp", (int)t);

            // Envoie de la commande
            if(!query.exec())qDebug()<<"ecrit pas";

        }
        db.close();
    }
}




void SerialPortReader::handleError(QSerialPort::SerialPortError serialPortError)
{
    if (serialPortError == QSerialPort::ReadError) {
        m_standardOutput << QObject::tr("An I/O error occurred while reading "
                                        "the data from port %1, error: %2")
                                .arg(m_serialPort->portName())
                                .arg(m_serialPort->errorString())
                         << "\n";
        QCoreApplication::exit(1);
    }
}

void SerialPortReader::handleTimeout()
{
    if (m_readData.isEmpty()) {
        m_standardOutput << QObject::tr("No data was currently available "
                                        "for reading from port %1")
                                .arg(m_serialPort->portName())
                         << "\n";
    } else {
        m_standardOutput << QObject::tr("Data successfully received from port %1")
        .arg(m_serialPort->portName())
            << "\n";
        m_standardOutput << m_readData << "\n";
    }

    QCoreApplication::quit();
}

/* --- MEMO ---
 * qDebug()<<QString::number(trame_uint8_t[i],16);
*/

