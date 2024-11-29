import express from "express";
import { collection, addDoc, query, where, getDocs, doc, updateDoc, deleteDoc, getDoc } from "firebase/firestore";
import jwt from "jsonwebtoken";
import cors from "cors";
import multer from "multer";
import { ref, uploadBytes, getDownloadURL } from "firebase/storage";
import { db, storage } from "./models/firebaseConfig.js";
import bcrypt from "bcrypt";
import http from "http";
import { Server } from "socket.io";
import validarToken from "./middlewares/auth.js";


// Inicialize o aplicativo Express
const app = express();
app.use(express.json());
app.use(cors()); // Configuração do CORS

// Configuração do multer para upload de arquivos
const upload = multer({ storage: multer.memoryStorage() }); // Armazena a imagem em memória

app.post('/jornal', upload.single('image'), async (req, res) => {
    try {
        // Extrai os dados do corpo da requisição
        const { numberTemplate, title, author, status, coluna, texts, qrCodeText1, qrCodeText2 } = req.body;

        // Se uma imagem foi enviada, ela estará disponível em req.file
        const image = req.file ? req.file.buffer.toString('base64') : null; // Codifica a imagem em base64

        // Prepara os dados para serem salvos no Firestore
        const dataToSave = {
            numberTemplate,
            title,
            author,
            status,
            coluna,
            texts: JSON.parse(texts), // Converte os textos para um array
            qrCodeText1,
            qrCodeText2,
            image, // Se a imagem foi enviada, ela será salva
            timestamp: new Date(), // Marca o momento do envio
        };

        // Salva os dados no Firestore
        const collectionRef = db.collection('edicao');
        await collectionRef.add(dataToSave);

        // Responde com sucesso
        res.status(201).json({ message: 'Dados enviados com sucesso!' });
    } catch (error) {
        console.error('Erro ao processar a requisição:', error);
        res.status(500).json({ error: 'Erro ao processar os dados' });
    }
});




// Endpoint para fazer o upload da imagem no Firebase Storage e salvar a URL no Firestore
app.post('/formulario', upload.single('image'), async (req, res) => {
    try {
        const { name, email, password, coluna, categoria, acesso, anoEscolar } = req.body;
        console.log("Dados recebidos:", { name, email, password, coluna, categoria, acesso, anoEscolar });

        // Verificando se a imagem foi enviada
        if (!req.file) {
            return res.status(400).json({ error: 'Nenhuma imagem foi enviada.' });
        }

        // Criptografando a senha antes de salvar
        const hashedPassword = await bcrypt.hash(password, 10); // O número 10 é o "salt rounds" para a hash

        // Agora, fazendo o upload da imagem para o Firebase Storage
        const { buffer, originalname } = req.file;
        const storageRef = ref(storage, `imagens/${originalname}`); // Definindo o caminho da imagem
        await uploadBytes(storageRef, buffer); // Upload da imagem

        // Obtendo a URL pública da imagem carregada
        const downloadURL = await getDownloadURL(storageRef);

        // Incluindo o usuário no banco de dados, incluindo a URL da imagem
        const userRef = await addDoc(collection(db, 'users'), { 
            name, 
            email, 
            password: hashedPassword, 
            coluna, 
            categoria, 
            acesso, 
            anoEscolar,
            imagemUrl: downloadURL
        });

        console.log("Usuário criado com sucesso!");

        // Retornando a resposta com sucesso
        res.status(201).json({
            mensagem: 'Usuário criado e imagem enviada com sucesso!',
            userId: userRef.id,
            imagemUrl: downloadURL,
        });
    } catch (error) {
        console.error('Erro ao criar usuário e enviar imagem:', error);
        res.status(500).json({ error: 'Erro ao criar usuário ou enviar imagem.' });
    }
});




// Rota GET para buscar imagens por userId
app.get('/imagens/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const querySnapshot = await getDocs(query(collection(db, 'imagens'), where('userId', '==', userId)));
        const images = querySnapshot.docs.map(doc => doc.data());
        res.status(200).json(images);
    } catch (error) {
        console.error('Erro ao buscar imagens:', error);
        res.status(500).json({ error: 'Erro ao buscar imagens.' });
    }
});





// Endpoint para criar coluna com upload de imagem
app.post('/colunas', upload.single('imageColumn'), async (req, res) => {
    try {
        const { columname, color, estadoColuna } = req.body; // Recebe os dados do corpo da requisição
        let downloadURL = null;

        // Se uma imagem foi enviada, faça o upload
        if (req.file) {
            const { buffer, originalname } = req.file;
            const storageRef = ref(storage, `colunas/${originalname}`);

            // Faz o upload da imagem para o Firebase
            await uploadBytes(storageRef, buffer);
            downloadURL = await getDownloadURL(storageRef);
        }

        // Cria um novo documento na coleção "colunas"
        const data = {
            columname,
            color,
            estadoColuna,
            imageColumn: downloadURL, // URL da imagem se foi enviada
        };

        const docRef = await addDoc(collection(db, 'colunas'), data);
        res.status(201).json({ id: docRef.id, data }); // Retorna o ID do documento criado e os dados
    } catch (error) {
        console.error('Erro ao criar coluna:', error);
        res.status(500).json({ error: 'Erro ao criar coluna.' });
    }
});
// Endpoint para deletar imagem de uma coluna
app.delete('/colunas/imagem', async (req, res) => {
    try {
        const { imagePath } = req.body; // Caminho da imagem no Firebase

        if (!imagePath) {
            return res.status(400).json({ error: 'Caminho da imagem é necessário.' });
        }

        // Referência ao arquivo no Firebase Storage
        const fileRef = ref(storage, imagePath);

        // Deleta o arquivo
        await deleteObject(fileRef);
        res.status(200).json({ message: 'Imagem deletada com sucesso.' });
    } catch (error) {
        console.error('Erro ao deletar imagem:', error);
        res.status(500).json({ error: 'Erro ao deletar imagem.' });
    }
});



// Endpoint para buscar colunas
app.get('/colunas', async (req, res) => {
    try {
        const colunasSnapshot = await getDocs(collection(db, 'colunas'));
        const colunas = colunasSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        res.status(200).json(colunas);
    } catch (error) {
        console.error('Erro ao buscar colunas:', error);
        res.status(500).json({ error: 'Erro ao buscar colunas.' });
    }
});


app.patch('/colunas/:id', async (req, res) => {
    const { id } = req.params; // ID da coluna a ser atualizada
    const { columname, color } = req.body; // Novos dados da coluna

    console.log("Dados recebidos para atualização:", { id, columname, color });

    try {
        // Busca o documento da coluna na coleção 'colunas'
        const colunasRef = doc(db, 'colunas', id);
        const colunasDoc = await getDoc(colunasRef);

        if (!colunasDoc.exists()) {
            return res.status(404).json({
                error: true,
                mensagem: "Coluna não encontrada."
            });
        }

        const oldColumname = colunasDoc.data().columname; // Nome atual da coluna
        console.log("Nome antigo da coluna:", oldColumname);

        // Atualiza o documento da coluna
        await updateDoc(colunasRef, {
            ...(columname && { columname }),
            ...(color && { color }),
        });

        console.log("Coluna atualizada com sucesso!");

        // Atualiza os usuários da coleção 'users' cujo campo 'coluna' corresponde ao novo valor
        if (columname) {
            const usersCollection = collection(db, 'users');
            const userSnapshot = await getDocs(usersCollection);

            const updatePromises = []; // Lista para armazenar promessas de atualizações
            userSnapshot.forEach(userDoc => {
                const userData = userDoc.data();

                if (userData.coluna === oldColumname) { // Filtra usuários com a coluna antiga
                    console.log(`Atualizando usuário: ${userDoc.id}, nova coluna: ${columname}`);
                    updatePromises.push(
                        updateDoc(doc(db, 'users', userDoc.id), { coluna: columname })
                    );
                }
            });

            await Promise.all(updatePromises); // Aguarda todas as atualizações
            console.log("Usuários atualizados com sucesso!");
        }

        return res.json({
            error: false,
            mensagem: "Coluna e usuários atualizados com sucesso!"
        });
    } catch (error) {
        console.error("Erro ao atualizar coluna ou usuários:", error);
        return res.status(500).json({
            error: true,
            mensagem: "Erro ao atualizar a coluna ou os usuários.",
            detalhes: error.message,
        });
    }
});



// Endpoint para obter todos os usuários
app.get('/users', async (req, res) => {
    try {
        const usersCollection = collection(db, "users");
        const userSnapshot = await getDocs(usersCollection);
        const users = userSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

        console.log("Usuários obtidos:", users);

        return res.json({
            error: false,
            mensagem: "Usuários selecionados com sucesso!",
            users
        });
    } catch (error) {
        console.error("Erro ao obter usuários:", error);
        return res.status(500).json({
            error: true,
            mensagem: "Erro ao obter usuários"
        });
    }
});



// Endpoint para obter um usuário por ID
app.get('/users/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const userDoc = await getDoc(doc(db, "users", id));
        if (userDoc.exists()) {
            const userData = userDoc.data();
            return res.json({
                error: false,
                mensagem: "Usuário selecionado com sucesso!",
                user: {
                    ...userData,
                    categoria: userData.categoria // Inclua a categoria na resposta
                }
            });
        } else {
            return res.status(400).json({
                error: true,
                mensagem: "Usuário não Cadastrado"
            });
        }
    } catch (error) {
        return res.status(500).json({
            error: true,
            mensagem: "Erro ao obter usuário"
        });
    }
});

app.post('/calendario', async (req, res) => {
    try {
      // Extrair dados do corpo da requisição
      const { userId, agendaData } = req.body;
      console.log('userId:', userId);
      console.log('agendaData:', agendaData);
  
      // Verificar se os dados necessários estão presentes
      if (!userId || !agendaData) {
        return res.status(400).send('Faltando dados obrigatórios!');
      }
  
      // Referência ao documento de calendário do usuário
      const agendaRef = doc(db, "calendario", userId); 
      console.log('agendaRef:', agendaRef);
  
      // Salvar ou atualizar a agenda no Firestore (merge=true para não sobrescrever outros dados)
      await setDoc(agendaRef, { agendas: agendaData }, { merge: true });
  
      res.status(200).send('Agenda salva com sucesso!');
    } catch (error) {
      console.error("Erro ao salvar a agenda:", error);
      res.status(500).send('Erro ao salvar a agenda!');
    }
  });
  


// Endpoint para fixar ou desfixar um usuário por ID
// Rota para fixar ou desfixar usuário
app.patch('/fix-user/:id', async (req, res) => {
    const { id } = req.params;
    const { isFixed } = req.body; // Espera um booleano para indicar se o usuário deve ser fixado ou desfixado

    try {
        const userRef = doc(db, "users", id);
        await updateDoc(userRef, { isFixed });
        return res.json({
            error: false,
            mensagem: `Usuário ${isFixed ? 'fixado' : 'desfixado'} com sucesso!`
        });
    } catch (error) {
        return res.status(400).json({
            error: true,
            mensagem: "Não foi possível atualizar o status do usuário."
        });
    }
});



// Endpoint para validar o token
app.get('/val-token', validarToken, (req, res) => {
    res.json({
        error: false,
        mensagem: "Token válido"
    });
});


// Endpoint para criar um novo usuário

app.patch('/formulario/:id', async (req, res) => {
    const { id } = req.params; // Pega o ID da URL
    const { name, password, materia, categoria, coluna, anoEscolar, email } = req.body; // Pega os dados do corpo da requisição
    console.log("Dados recebidos para atualização:", { id, name, password, materia, categoria, coluna, anoEscolar, email }); // Log

    try {
        // Referência ao documento do usuário a ser atualizado
        const userRef = doc(db, 'users', id); // Usando o 'id' como ID do documento

        // Atualiza os campos no Firestore
        await updateDoc(userRef, {
            ...(email && { email }),          // Atualiza 'name' se estiver presente
            ...(password && { password }),  // Atualiza 'password' se estiver presente
            ...(anoEscolar && { anoEscolar }),    // Atualiza 'materia' se estiver presente
            ...(categoria && { categoria }),  // Atualiza 'categoria' se estiver presente
            ...(coluna && { coluna })  // Atualiza 'categoria' se estiver presente
        });

        console.log("Usuário atualizado com sucesso!");
        return res.json({
            error: false,
            mensagem: "Usuário atualizado com sucesso!"
        });
    } catch (error) {
        console.error("Erro ao atualizar usuário:", error);
        return res.status(400).json({
            error: true,
            mensagem: "Usuário não atualizado"
        });
    }
});


app.post('/formularioComum', async (req, res) => {
    const { name, email, password,c} = req.body;
    console.log("Dados recebidos:", { name, email, password,acesso});

    try {
        // Criptografando a senha antes de salvar
        const hashedPassword = await bcrypt.hash(password, 10); // O número 10 é o "salt rounds" para a hash

        // Incluindo a senha criptografada no banco de dados
        await addDoc(collection(db, 'users'), { 
            name, 
            email, 
            password: hashedPassword, // Usando a senha criptografada
            acesso: "comum"   
        });

        console.log("Usuário cadastrado com sucesso!");
        return res.json({
            error: false,
            mensagem: "Usuário cadastrado com sucesso!"
        });
    } catch (error) {
        console.error("Erro ao cadastrar usuário:", error);
        return res.status(400).json({
            error: true,
            mensagem: "Usuário não cadastrado"
        });
    }
});

// Endpoint para atualizar a senha de um usuário
app.put('/senha/:id', async (req, res) => {
    const { id } = req.params;
    const { password } = req.body;

    try {
        const userRef = doc(db, "users", id);
        await updateDoc(userRef, { password });
        return res.json({
            error: false,
            mensagem: "Senha atualizada com sucesso!"
        });
    } catch (error) {
        return res.status(400).json({
            error: true,
            mensagem: "Não foi possível atualizar"
        });
    }
});

// Endpoint para deletar um usuário por ID
app.delete('/users/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const userRef = doc(db, "users", id);
        await deleteDoc(userRef);
        return res.json({
            error: false,
            mensagem: "Usuário deletado com sucesso!"
        });
    } catch (error) {
        return res.status(400).json({
            error: true,
            mensagem: "Não foi possível deletar"
        });
    }
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Buscando o usuário pelo email na coleção 'users'
        const usersCollection = collection(db, "users");
        const userSnapshot = await getDocs(query(usersCollection, where("email", "==", email)));

        // Verifica se o usuário existe
        if (userSnapshot.empty) {
            return res.status(400).json({
                error: true,
                mensagem: "Usuário não encontrado!"
            });
        }

        const userDoc = userSnapshot.docs[0];
        const user = userDoc.data();

        // Usando bcrypt para comparar a senha fornecida com o hash armazenado
        const isPasswordValid = await bcrypt.compare(password, user.password);

        // Se a senha estiver incorreta, retornar erro
        if (!isPasswordValid) {
            return res.status(400).json({
                error: true,
                mensagem: "Senha incorreta!"
            });
        }

        // Gerando o token JWT
        const token = jwt.sign({ id: userDoc.id, email: user.email, categoria: user.categoria }, process.env.SECRET, {
            expiresIn: "7d" // Definindo o tempo de expiração do token
        });

        // Retornando sucesso com o token e categoria do usuário
        return res.json({
            error: false,
            mensagem: "Login realizado com sucesso!",
            token,
            categoria: user.categoria ,// Incluindo a categoria do usuário
            coluna: user.coluna,
            acesso: user.acesso
        });

    } catch (error) {
        console.error("Erro ao realizar login:", error);
        return res.status(500).json({
            error: true,
            mensagem: "Erro ao realizar login",
            detalhe: error.message
        });
    }
});



app.post('/sendMessage', async (req, res) => {
    const { text, user, recipientId } = req.body;

    try {
        const messageData = {
            text,
            user,
            recipientId,
            timestamp: new Date(),
        };

        // Adiciona a mensagem à coleção 'chat'
        await db.collection('chat').add(messageData);
        res.status(201).send({ message: 'Mensagem enviada com sucesso!' });
    } catch (error) {
        console.error("Erro ao enviar a mensagem:", error);
        res.status(500).send({ error: 'Erro ao enviar a mensagem' });
    }
});


app.post('/colunas', async (req, res) => {
    const { columname, color } = req.body; // Recebe os campos 'columname' e 'color' do corpo da requisição

    if (!columname) {
        return res.status(400).json({
            error: true,
            mensagem: "O campo 'columname' é obrigatório."
        });
    }

    // Verifica se o campo 'color' é fornecido
    if (!color) {
        return res.status(400).json({
            error: true,
            mensagem: "O campo 'color' é obrigatório."
        });
    }

    try {
        // Adiciona um novo documento à coleção 'colunas' com os campos 'columname' e 'color'
        await addDoc(collection(db, 'colunas'), { columname, color });
        console.log("Coluna cadastrada com sucesso!");
        return res.json({
            error: false,
            mensagem: "Coluna cadastrada com sucesso!"
        });
    } catch (error) {
        console.error("Erro ao cadastrar coluna:", error);
        return res.status(400).json({
            error: true,
            mensagem: "Coluna não cadastrada."
        });
    }
});

app.patch('/colunas/:id', async (req, res) => {
    const { id } = req.params; // ID da coluna a ser atualizada
    const { columname, color } = req.body; // Novos dados da coluna
    console.log("Dados recebidos para atualização:", { id, columname, color }); // Log

    try {
        // Atualiza a coluna na coleção 'colunas'
        const colunasRef = doc(db, 'colunas', id);
        await updateDoc(colunasRef, {
            ...(columname && { columname }), // Atualiza o nome da coluna
            ...(color && { color }) // Atualiza a cor da coluna
        });

        // Atualiza todos os usuários que possuem o campo "coluna" igual ao valor de columname
        if (columname) {
            const usersCollection = collection(db, 'users');
            const userSnapshot = await getDocs(usersCollection);

            // Atualiza cada usuário encontrado
            const updatePromises = [];
            userSnapshot.forEach(doc => {
                const user = doc.data();
                if (user.coluna === columname) {
                    // Atualiza o campo "coluna" do usuário
                    updatePromises.push(
                        updateDoc(doc.ref, { coluna: columname })
                    );
                }
            });

            // Aguarda todas as atualizações
            await Promise.all(updatePromises);
        }

        console.log("Coluna e usuários atualizados com sucesso!");
        return res.json({
            error: false,
            mensagem: "Coluna e usuários atualizados com sucesso!"
        });
    } catch (error) {
        console.error("Erro ao atualizar coluna ou usuários:", error);
        return res.status(400).json({
            error: true,
            mensagem: "Erro ao atualizar a coluna ou os usuários."
        });
    }
});



app.get('/colunas', async (req, res) => {
    try {
        const colunasSnapshot = await getDocs(collection(db, 'colunas'));
        const colunasList = colunasSnapshot.docs.map(doc => ({
            id: doc.id, // Adiciona o ID do documento
            ...doc.data() // Adiciona os dados do documento
        }));

        return res.json(colunasList);
    } catch (error) {
        console.error("Erro ao buscar colunas:", error);
        return res.status(500).json({
            error: true,
            mensagem: "Erro ao buscar colunas."
        });
    }
});

app.get('/notificacoes', async (req, res) => {
    try {
        const colunasSnapshot = await getDocs(collection(db, 'notificacoes'));
        const colunasList = colunasSnapshot.docs.map(doc => ({
            id: doc.id, // Adiciona o ID do documento
            ...doc.data() // Adiciona os dados do documento
        }));

        return res.json(colunasList);
    } catch (error) {
        console.error("Erro ao buscar colunas:", error);
        return res.status(500).json({
            error: true,
            mensagem: "Erro ao buscar colunas."
        });
    }
});
app.delete('/notificacoes/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const userRef = doc(db, "notificacoes", id);
        await deleteDoc(userRef);
        return res.json({
            error: false,
            mensagem: "card deletado com sucesso!"
        });
    } catch (error) {
        return res.status(400).json({
            error: true,
            mensagem: "Não foi possível deletar"
        });
    }
});


// Endpoint para atualizar a coluna


app.delete('/colunas', async (req, res) => {
    try {
        const colRef = collection(db, 'colunas'); // Referência à coleção
        const querySnapshot = await getDocs(colRef); // Obtém todos os documentos da coleção

        const deletePromises = querySnapshot.docs.map(doc => deleteDoc(doc.ref)); // Cria um array de promessas para deletar cada documento

        await Promise.all(deletePromises); // Aguarda a conclusão de todas as promessas

        console.log("Todas as colunas deletadas com sucesso!");
        return res.json({
            error: false,
            mensagem: "Todas as colunas deletadas com sucesso!"
        });
    } catch (error) {
        console.error("Erro ao deletar colunas:", error);
        return res.status(400).json({
            error: true,
            mensagem: "Erro ao deletar colunas."
        });
    }
});


app.delete('/colunas/:id', async (req, res) => {
    const { id } = req.params; // Obtém o ID do documento a ser deletado

    try {
        const colRef = doc(db, 'colunas', id); // Referência ao documento específico
        await deleteDoc(colRef); // Deleta o documento
        console.log(`Coluna com ID ${id} deletada com sucesso!`);
        return res.json({
            error: false,
            mensagem: "Coluna deletada com sucesso!"
        });
    } catch (error) {
        console.error("Erro ao deletar coluna:", error);
        return res.status(400).json({
            error: true,
            mensagem: "Erro ao deletar coluna."
        });
    }
});



// Criação do servidor HTTP
const server = http.createServer(app);

// Inicialize o servidor Socket.io
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

io.on("connection", (socket) => {
    console.log("Usuário conectado:", socket.id);

    socket.on("chat message", (msg) => {
        console.log("Mensagem recebida:", msg);
        io.emit("chat message", msg);
    });

    socket.on("user typing", (user) => {
        console.log(`${user} está digitando`);
        io.emit("user typing", user);
    });

    socket.on("stop typing", (user) => {
        console.log(`${user} parou de digitar`);
        io.emit("stop typing", user);
    });

    socket.on("disconnect", () => {
        console.log("Usuário desconectado:", socket.id);
    });
});

// Inicia o servidor
const PORT = 8181;
const HOST = "0.0.0.0"
server.listen(PORT, HOST, () => {
    console.log(`Servidor Express e Socket.io iniciado na porta ${PORT}`);
});
