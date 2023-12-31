// This file is generated by rust-protobuf 3.2.0. Do not edit
// .proto file is parsed by pure
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `transform.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_2_0;

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:ironcorelabs.proto.PublicKey)
pub struct PublicKey {
    // message fields
    // @@protoc_insertion_point(field:ironcorelabs.proto.PublicKey.x)
    pub x: ::bytes::Bytes,
    // @@protoc_insertion_point(field:ironcorelabs.proto.PublicKey.y)
    pub y: ::bytes::Bytes,
    // special fields
    // @@protoc_insertion_point(special_field:ironcorelabs.proto.PublicKey.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a PublicKey {
    fn default() -> &'a PublicKey {
        <PublicKey as ::protobuf::Message>::default_instance()
    }
}

impl PublicKey {
    pub fn new() -> PublicKey {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "x",
            |m: &PublicKey| { &m.x },
            |m: &mut PublicKey| { &mut m.x },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "y",
            |m: &PublicKey| { &m.y },
            |m: &mut PublicKey| { &mut m.y },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<PublicKey>(
            "PublicKey",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for PublicKey {
    const NAME: &'static str = "PublicKey";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.x = is.read_tokio_bytes()?;
                },
                18 => {
                    self.y = is.read_tokio_bytes()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.x.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.x);
        }
        if !self.y.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.y);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.x.is_empty() {
            os.write_bytes(1, &self.x)?;
        }
        if !self.y.is_empty() {
            os.write_bytes(2, &self.y)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> PublicKey {
        PublicKey::new()
    }

    fn clear(&mut self) {
        self.x.clear();
        self.y.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static PublicKey {
        static instance: PublicKey = PublicKey {
            x: ::bytes::Bytes::new(),
            y: ::bytes::Bytes::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for PublicKey {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("PublicKey").unwrap()).clone()
    }
}

impl ::std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PublicKey {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:ironcorelabs.proto.UserOrGroup)
pub struct UserOrGroup {
    // message fields
    // @@protoc_insertion_point(field:ironcorelabs.proto.UserOrGroup.masterPublicKey)
    pub masterPublicKey: ::protobuf::MessageField<PublicKey>,
    // message oneof groups
    pub UserOrGroupId: ::std::option::Option<user_or_group::UserOrGroupId>,
    // special fields
    // @@protoc_insertion_point(special_field:ironcorelabs.proto.UserOrGroup.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a UserOrGroup {
    fn default() -> &'a UserOrGroup {
        <UserOrGroup as ::protobuf::Message>::default_instance()
    }
}

impl UserOrGroup {
    pub fn new() -> UserOrGroup {
        ::std::default::Default::default()
    }

    // string userId = 1;

    pub fn userId(&self) -> &str {
        match self.UserOrGroupId {
            ::std::option::Option::Some(user_or_group::UserOrGroupId::UserId(ref v)) => v,
            _ => "",
        }
    }

    pub fn clear_userId(&mut self) {
        self.UserOrGroupId = ::std::option::Option::None;
    }

    pub fn has_userId(&self) -> bool {
        match self.UserOrGroupId {
            ::std::option::Option::Some(user_or_group::UserOrGroupId::UserId(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_userId(&mut self, v: ::protobuf::Chars) {
        self.UserOrGroupId = ::std::option::Option::Some(user_or_group::UserOrGroupId::UserId(v))
    }

    // Mutable pointer to the field.
    pub fn mut_userId(&mut self) -> &mut ::protobuf::Chars {
        if let ::std::option::Option::Some(user_or_group::UserOrGroupId::UserId(_)) = self.UserOrGroupId {
        } else {
            self.UserOrGroupId = ::std::option::Option::Some(user_or_group::UserOrGroupId::UserId(::protobuf::Chars::new()));
        }
        match self.UserOrGroupId {
            ::std::option::Option::Some(user_or_group::UserOrGroupId::UserId(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_userId(&mut self) -> ::protobuf::Chars {
        if self.has_userId() {
            match self.UserOrGroupId.take() {
                ::std::option::Option::Some(user_or_group::UserOrGroupId::UserId(v)) => v,
                _ => panic!(),
            }
        } else {
            ::protobuf::Chars::new()
        }
    }

    // string groupId = 2;

    pub fn groupId(&self) -> &str {
        match self.UserOrGroupId {
            ::std::option::Option::Some(user_or_group::UserOrGroupId::GroupId(ref v)) => v,
            _ => "",
        }
    }

    pub fn clear_groupId(&mut self) {
        self.UserOrGroupId = ::std::option::Option::None;
    }

    pub fn has_groupId(&self) -> bool {
        match self.UserOrGroupId {
            ::std::option::Option::Some(user_or_group::UserOrGroupId::GroupId(..)) => true,
            _ => false,
        }
    }

    // Param is passed by value, moved
    pub fn set_groupId(&mut self, v: ::protobuf::Chars) {
        self.UserOrGroupId = ::std::option::Option::Some(user_or_group::UserOrGroupId::GroupId(v))
    }

    // Mutable pointer to the field.
    pub fn mut_groupId(&mut self) -> &mut ::protobuf::Chars {
        if let ::std::option::Option::Some(user_or_group::UserOrGroupId::GroupId(_)) = self.UserOrGroupId {
        } else {
            self.UserOrGroupId = ::std::option::Option::Some(user_or_group::UserOrGroupId::GroupId(::protobuf::Chars::new()));
        }
        match self.UserOrGroupId {
            ::std::option::Option::Some(user_or_group::UserOrGroupId::GroupId(ref mut v)) => v,
            _ => panic!(),
        }
    }

    // Take field
    pub fn take_groupId(&mut self) -> ::protobuf::Chars {
        if self.has_groupId() {
            match self.UserOrGroupId.take() {
                ::std::option::Option::Some(user_or_group::UserOrGroupId::GroupId(v)) => v,
                _ => panic!(),
            }
        } else {
            ::protobuf::Chars::new()
        }
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(3);
        let mut oneofs = ::std::vec::Vec::with_capacity(1);
        fields.push(::protobuf::reflect::rt::v2::make_oneof_deref_has_get_set_simpler_accessor::<_, _>(
            "userId",
            UserOrGroup::has_userId,
            UserOrGroup::userId,
            UserOrGroup::set_userId,
        ));
        fields.push(::protobuf::reflect::rt::v2::make_oneof_deref_has_get_set_simpler_accessor::<_, _>(
            "groupId",
            UserOrGroup::has_groupId,
            UserOrGroup::groupId,
            UserOrGroup::set_groupId,
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, PublicKey>(
            "masterPublicKey",
            |m: &UserOrGroup| { &m.masterPublicKey },
            |m: &mut UserOrGroup| { &mut m.masterPublicKey },
        ));
        oneofs.push(user_or_group::UserOrGroupId::generated_oneof_descriptor_data());
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<UserOrGroup>(
            "UserOrGroup",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for UserOrGroup {
    const NAME: &'static str = "UserOrGroup";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.UserOrGroupId = ::std::option::Option::Some(user_or_group::UserOrGroupId::UserId(is.read_tokio_chars()?));
                },
                18 => {
                    self.UserOrGroupId = ::std::option::Option::Some(user_or_group::UserOrGroupId::GroupId(is.read_tokio_chars()?));
                },
                26 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.masterPublicKey)?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.masterPublicKey.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if let ::std::option::Option::Some(ref v) = self.UserOrGroupId {
            match v {
                &user_or_group::UserOrGroupId::UserId(ref v) => {
                    my_size += ::protobuf::rt::string_size(1, &v);
                },
                &user_or_group::UserOrGroupId::GroupId(ref v) => {
                    my_size += ::protobuf::rt::string_size(2, &v);
                },
            };
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.masterPublicKey.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(3, v, os)?;
        }
        if let ::std::option::Option::Some(ref v) = self.UserOrGroupId {
            match v {
                &user_or_group::UserOrGroupId::UserId(ref v) => {
                    os.write_string(1, v)?;
                },
                &user_or_group::UserOrGroupId::GroupId(ref v) => {
                    os.write_string(2, v)?;
                },
            };
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> UserOrGroup {
        UserOrGroup::new()
    }

    fn clear(&mut self) {
        self.UserOrGroupId = ::std::option::Option::None;
        self.UserOrGroupId = ::std::option::Option::None;
        self.masterPublicKey.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static UserOrGroup {
        static instance: UserOrGroup = UserOrGroup {
            masterPublicKey: ::protobuf::MessageField::none(),
            UserOrGroupId: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for UserOrGroup {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("UserOrGroup").unwrap()).clone()
    }
}

impl ::std::fmt::Display for UserOrGroup {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UserOrGroup {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

/// Nested message and enums of message `UserOrGroup`
pub mod user_or_group {

    #[derive(Clone,PartialEq,Debug)]
    #[non_exhaustive]
    // @@protoc_insertion_point(oneof:ironcorelabs.proto.UserOrGroup.UserOrGroupId)
    pub enum UserOrGroupId {
        // @@protoc_insertion_point(oneof_field:ironcorelabs.proto.UserOrGroup.userId)
        UserId(::protobuf::Chars),
        // @@protoc_insertion_point(oneof_field:ironcorelabs.proto.UserOrGroup.groupId)
        GroupId(::protobuf::Chars),
    }

    impl ::protobuf::Oneof for UserOrGroupId {
    }

    impl ::protobuf::OneofFull for UserOrGroupId {
        fn descriptor() -> ::protobuf::reflect::OneofDescriptor {
            static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::OneofDescriptor> = ::protobuf::rt::Lazy::new();
            descriptor.get(|| <super::UserOrGroup as ::protobuf::MessageFull>::descriptor().oneof_by_name("UserOrGroupId").unwrap()).clone()
        }
    }

    impl UserOrGroupId {
        pub(in super) fn generated_oneof_descriptor_data() -> ::protobuf::reflect::GeneratedOneofDescriptorData {
            ::protobuf::reflect::GeneratedOneofDescriptorData::new::<UserOrGroupId>("UserOrGroupId")
        }
    }
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:ironcorelabs.proto.EncryptedDekData)
pub struct EncryptedDekData {
    // message fields
    // @@protoc_insertion_point(field:ironcorelabs.proto.EncryptedDekData.encryptedBytes)
    pub encryptedBytes: ::bytes::Bytes,
    // @@protoc_insertion_point(field:ironcorelabs.proto.EncryptedDekData.ephemeralPublicKey)
    pub ephemeralPublicKey: ::protobuf::MessageField<PublicKey>,
    // @@protoc_insertion_point(field:ironcorelabs.proto.EncryptedDekData.signature)
    pub signature: ::bytes::Bytes,
    // @@protoc_insertion_point(field:ironcorelabs.proto.EncryptedDekData.authHash)
    pub authHash: ::bytes::Bytes,
    // @@protoc_insertion_point(field:ironcorelabs.proto.EncryptedDekData.publicSigningKey)
    pub publicSigningKey: ::bytes::Bytes,
    // special fields
    // @@protoc_insertion_point(special_field:ironcorelabs.proto.EncryptedDekData.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a EncryptedDekData {
    fn default() -> &'a EncryptedDekData {
        <EncryptedDekData as ::protobuf::Message>::default_instance()
    }
}

impl EncryptedDekData {
    pub fn new() -> EncryptedDekData {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(5);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "encryptedBytes",
            |m: &EncryptedDekData| { &m.encryptedBytes },
            |m: &mut EncryptedDekData| { &mut m.encryptedBytes },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, PublicKey>(
            "ephemeralPublicKey",
            |m: &EncryptedDekData| { &m.ephemeralPublicKey },
            |m: &mut EncryptedDekData| { &mut m.ephemeralPublicKey },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "signature",
            |m: &EncryptedDekData| { &m.signature },
            |m: &mut EncryptedDekData| { &mut m.signature },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "authHash",
            |m: &EncryptedDekData| { &m.authHash },
            |m: &mut EncryptedDekData| { &mut m.authHash },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "publicSigningKey",
            |m: &EncryptedDekData| { &m.publicSigningKey },
            |m: &mut EncryptedDekData| { &mut m.publicSigningKey },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<EncryptedDekData>(
            "EncryptedDekData",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for EncryptedDekData {
    const NAME: &'static str = "EncryptedDekData";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.encryptedBytes = is.read_tokio_bytes()?;
                },
                18 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.ephemeralPublicKey)?;
                },
                26 => {
                    self.signature = is.read_tokio_bytes()?;
                },
                34 => {
                    self.authHash = is.read_tokio_bytes()?;
                },
                42 => {
                    self.publicSigningKey = is.read_tokio_bytes()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.encryptedBytes.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.encryptedBytes);
        }
        if let Some(v) = self.ephemeralPublicKey.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if !self.signature.is_empty() {
            my_size += ::protobuf::rt::bytes_size(3, &self.signature);
        }
        if !self.authHash.is_empty() {
            my_size += ::protobuf::rt::bytes_size(4, &self.authHash);
        }
        if !self.publicSigningKey.is_empty() {
            my_size += ::protobuf::rt::bytes_size(5, &self.publicSigningKey);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.encryptedBytes.is_empty() {
            os.write_bytes(1, &self.encryptedBytes)?;
        }
        if let Some(v) = self.ephemeralPublicKey.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(2, v, os)?;
        }
        if !self.signature.is_empty() {
            os.write_bytes(3, &self.signature)?;
        }
        if !self.authHash.is_empty() {
            os.write_bytes(4, &self.authHash)?;
        }
        if !self.publicSigningKey.is_empty() {
            os.write_bytes(5, &self.publicSigningKey)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> EncryptedDekData {
        EncryptedDekData::new()
    }

    fn clear(&mut self) {
        self.encryptedBytes.clear();
        self.ephemeralPublicKey.clear();
        self.signature.clear();
        self.authHash.clear();
        self.publicSigningKey.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static EncryptedDekData {
        static instance: EncryptedDekData = EncryptedDekData {
            encryptedBytes: ::bytes::Bytes::new(),
            ephemeralPublicKey: ::protobuf::MessageField::none(),
            signature: ::bytes::Bytes::new(),
            authHash: ::bytes::Bytes::new(),
            publicSigningKey: ::bytes::Bytes::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for EncryptedDekData {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("EncryptedDekData").unwrap()).clone()
    }
}

impl ::std::fmt::Display for EncryptedDekData {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for EncryptedDekData {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:ironcorelabs.proto.EncryptedDek)
pub struct EncryptedDek {
    // message fields
    // @@protoc_insertion_point(field:ironcorelabs.proto.EncryptedDek.userOrGroup)
    pub userOrGroup: ::protobuf::MessageField<UserOrGroup>,
    // @@protoc_insertion_point(field:ironcorelabs.proto.EncryptedDek.encryptedDekData)
    pub encryptedDekData: ::protobuf::MessageField<EncryptedDekData>,
    // special fields
    // @@protoc_insertion_point(special_field:ironcorelabs.proto.EncryptedDek.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a EncryptedDek {
    fn default() -> &'a EncryptedDek {
        <EncryptedDek as ::protobuf::Message>::default_instance()
    }
}

impl EncryptedDek {
    pub fn new() -> EncryptedDek {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, UserOrGroup>(
            "userOrGroup",
            |m: &EncryptedDek| { &m.userOrGroup },
            |m: &mut EncryptedDek| { &mut m.userOrGroup },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, EncryptedDekData>(
            "encryptedDekData",
            |m: &EncryptedDek| { &m.encryptedDekData },
            |m: &mut EncryptedDek| { &mut m.encryptedDekData },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<EncryptedDek>(
            "EncryptedDek",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for EncryptedDek {
    const NAME: &'static str = "EncryptedDek";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.userOrGroup)?;
                },
                18 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.encryptedDekData)?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.userOrGroup.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if let Some(v) = self.encryptedDekData.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.userOrGroup.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
        }
        if let Some(v) = self.encryptedDekData.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(2, v, os)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> EncryptedDek {
        EncryptedDek::new()
    }

    fn clear(&mut self) {
        self.userOrGroup.clear();
        self.encryptedDekData.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static EncryptedDek {
        static instance: EncryptedDek = EncryptedDek {
            userOrGroup: ::protobuf::MessageField::none(),
            encryptedDekData: ::protobuf::MessageField::none(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for EncryptedDek {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("EncryptedDek").unwrap()).clone()
    }
}

impl ::std::fmt::Display for EncryptedDek {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for EncryptedDek {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:ironcorelabs.proto.EncryptedDeks)
pub struct EncryptedDeks {
    // message fields
    // @@protoc_insertion_point(field:ironcorelabs.proto.EncryptedDeks.edeks)
    pub edeks: ::std::vec::Vec<EncryptedDek>,
    // @@protoc_insertion_point(field:ironcorelabs.proto.EncryptedDeks.documentId)
    pub documentId: ::protobuf::Chars,
    // @@protoc_insertion_point(field:ironcorelabs.proto.EncryptedDeks.segmentId)
    pub segmentId: i32,
    // special fields
    // @@protoc_insertion_point(special_field:ironcorelabs.proto.EncryptedDeks.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a EncryptedDeks {
    fn default() -> &'a EncryptedDeks {
        <EncryptedDeks as ::protobuf::Message>::default_instance()
    }
}

impl EncryptedDeks {
    pub fn new() -> EncryptedDeks {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(3);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "edeks",
            |m: &EncryptedDeks| { &m.edeks },
            |m: &mut EncryptedDeks| { &mut m.edeks },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "documentId",
            |m: &EncryptedDeks| { &m.documentId },
            |m: &mut EncryptedDeks| { &mut m.documentId },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "segmentId",
            |m: &EncryptedDeks| { &m.segmentId },
            |m: &mut EncryptedDeks| { &mut m.segmentId },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<EncryptedDeks>(
            "EncryptedDeks",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for EncryptedDeks {
    const NAME: &'static str = "EncryptedDeks";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.edeks.push(is.read_message()?);
                },
                18 => {
                    self.documentId = is.read_tokio_chars()?;
                },
                24 => {
                    self.segmentId = is.read_int32()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        for value in &self.edeks {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        };
        if !self.documentId.is_empty() {
            my_size += ::protobuf::rt::string_size(2, &self.documentId);
        }
        if self.segmentId != 0 {
            my_size += ::protobuf::rt::int32_size(3, self.segmentId);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        for v in &self.edeks {
            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
        };
        if !self.documentId.is_empty() {
            os.write_string(2, &self.documentId)?;
        }
        if self.segmentId != 0 {
            os.write_int32(3, self.segmentId)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> EncryptedDeks {
        EncryptedDeks::new()
    }

    fn clear(&mut self) {
        self.edeks.clear();
        self.documentId.clear();
        self.segmentId = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static EncryptedDeks {
        static instance: EncryptedDeks = EncryptedDeks {
            edeks: ::std::vec::Vec::new(),
            documentId: ::protobuf::Chars::new(),
            segmentId: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for EncryptedDeks {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("EncryptedDeks").unwrap()).clone()
    }
}

impl ::std::fmt::Display for EncryptedDeks {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for EncryptedDeks {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x0ftransform.proto\x12\x12ironcorelabs.proto\"'\n\tPublicKey\x12\x0c\
    \n\x01x\x18\x01\x20\x01(\x0cR\x01x\x12\x0c\n\x01y\x18\x02\x20\x01(\x0cR\
    \x01y\"\x9d\x01\n\x0bUserOrGroup\x12\x18\n\x06userId\x18\x01\x20\x01(\tH\
    \0R\x06userId\x12\x1a\n\x07groupId\x18\x02\x20\x01(\tH\0R\x07groupId\x12\
    G\n\x0fmasterPublicKey\x18\x03\x20\x01(\x0b2\x1d.ironcorelabs.proto.Publ\
    icKeyR\x0fmasterPublicKeyB\x0f\n\rUserOrGroupId\"\xef\x01\n\x10Encrypted\
    DekData\x12&\n\x0eencryptedBytes\x18\x01\x20\x01(\x0cR\x0eencryptedBytes\
    \x12M\n\x12ephemeralPublicKey\x18\x02\x20\x01(\x0b2\x1d.ironcorelabs.pro\
    to.PublicKeyR\x12ephemeralPublicKey\x12\x1c\n\tsignature\x18\x03\x20\x01\
    (\x0cR\tsignature\x12\x1a\n\x08authHash\x18\x04\x20\x01(\x0cR\x08authHas\
    h\x12*\n\x10publicSigningKey\x18\x05\x20\x01(\x0cR\x10publicSigningKey\"\
    \xa3\x01\n\x0cEncryptedDek\x12A\n\x0buserOrGroup\x18\x01\x20\x01(\x0b2\
    \x1f.ironcorelabs.proto.UserOrGroupR\x0buserOrGroup\x12P\n\x10encryptedD\
    ekData\x18\x02\x20\x01(\x0b2$.ironcorelabs.proto.EncryptedDekDataR\x10en\
    cryptedDekData\"\x85\x01\n\rEncryptedDeks\x126\n\x05edeks\x18\x01\x20\
    \x03(\x0b2\x20.ironcorelabs.proto.EncryptedDekR\x05edeks\x12\x1e\n\ndocu\
    mentId\x18\x02\x20\x01(\tR\ndocumentId\x12\x1c\n\tsegmentId\x18\x03\x20\
    \x01(\x05R\tsegmentIdB\x18\n\x16com.ironcorelabs.protob\x06proto3\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(0);
            let mut messages = ::std::vec::Vec::with_capacity(5);
            messages.push(PublicKey::generated_message_descriptor_data());
            messages.push(UserOrGroup::generated_message_descriptor_data());
            messages.push(EncryptedDekData::generated_message_descriptor_data());
            messages.push(EncryptedDek::generated_message_descriptor_data());
            messages.push(EncryptedDeks::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(0);
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}
